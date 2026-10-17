//! Wires configuration, state, approvals, gateway and executions into one handle

use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

use crate::{
    admin::attach_action,
    approvals::{Approvals, NO_APPROVAL_PAGE, NO_NOTIFIER},
    companion::DeviceTrust,
    config::{Config, ConfigError},
    executions::Executions,
    executor::{Executor, ExecutorError},
    gateway::{Gateway, UpstreamAccess},
    mac::{Mac, OnMac},
    notify::{Notifier, Ntfy},
    oauth::OAuth,
    passkeys::{PasskeyError, Passkeys},
    secrets::{
        Secrets,
        handoff::{self, TakenOver},
    },
    snapshot::Sealer,
    store::{Store, StoreError},
    usage::UsageLog,
};

/// Failures starting the app
#[derive(Debug, thiserror::Error)]
pub enum AppError {
    /// The configuration is unusable
    #[error(transparent)]
    Config(#[from] ConfigError),
    /// The database could not be opened
    #[error(transparent)]
    Store(#[from] StoreError),
    /// The executor could not start
    #[error(transparent)]
    Executor(#[from] ExecutorError),
    /// The relying party could not be set up
    #[error(transparent)]
    Passkey(#[from] PasskeyError),
}

/// Freezes durable state when the last handle to an [`App`] goes away
///
/// Tearing a process down drops the tasks that wait on approvals and on
/// results, and a dropped waiter looks like an abandoned request. Freezing
/// first makes every exit that skipped [`App::halt`] (an early return, a
/// panic, a dropped runtime) leave the stored state for the next boot, and
/// only an explicit outcome settles anything
struct Teardown {
    gateway: Arc<Gateway>,
    executions: Arc<Executions>,
}

impl Drop for Teardown {
    fn drop(&mut self) {
        self.gateway.approvals().freeze();
        self.executions.halt();
    }
}

/// Freezes the app's durable state when dropped; see [`App::freeze_on_drop`]
pub struct FreezeOnDrop(App);

impl Drop for FreezeOnDrop {
    fn drop(&mut self) {
        self.0.halt();
    }
}

/// How long a stop waits for the secrets to be free to hand off
const HAND_OFF_WAIT: std::time::Duration = std::time::Duration::from_secs(2);

/// Whether an app is the daemon, which alone takes over and hands off the
/// secrets of a restart
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Role {
    Daemon,
    OneOff,
}

/// A running codemode instance; cheap to clone
#[derive(Clone)]
pub struct App {
    _teardown: Arc<Teardown>,
    config: Arc<Config>,
    state_dir: PathBuf,
    role: Role,
    gateway: Arc<Gateway>,
    executions: Arc<Executions>,
    passkeys: Arc<Passkeys>,
    store: Store,
    log: UsageLog,
}

impl App {
    /// Starts state, upstream connections and the worker pool, notifying
    /// through the configured ntfy topic and, on macOS, asking on the Mac
    /// while the owner is at it
    pub async fn start(config: Config) -> Result<Self, AppError> {
        let notifier: Option<Arc<dyn Notifier>> = match config.notify.resolve_ntfy() {
            Ok(Some(ntfy)) => Some(Arc::new(Ntfy::new(ntfy))),
            Ok(None) => None,
            Err(error) => {
                // a broken homebased config must not take the gateway down;
                // `ask` tools are refused until it is fixed
                tracing::warn!(%error, "no approval notifications");

                None
            }
        };

        #[cfg(target_os = "macos")]
        let mac: Option<Arc<dyn Mac>> = Some(Arc::new(crate::mac::MacOs::new()));
        #[cfg(not(target_os = "macos"))]
        let mac: Option<Arc<dyn Mac>> = None;

        Self::start_with(config, notifier, mac).await
    }

    /// Like [`App::start`] with a caller-supplied notifier and Mac; a `None`
    /// notifier refuses every `ask` call, and a `None` Mac asks on the phone
    /// only
    pub async fn start_with(
        config: Config,
        notifier: Option<Arc<dyn Notifier>>,
        mac: Option<Arc<dyn Mac>>,
    ) -> Result<Self, AppError> {
        Self::build(config, notifier, mac, NO_NOTIFIER, Role::Daemon).await
    }

    /// For one-off runs outside the daemon: nobody can reach an approval
    /// page, so `ask` calls are refused with a reason saying so
    ///
    /// The run leaves the daemon its fixed iroh address and its phones:
    /// binding `secrets.listen` would fail while the daemon holds it, and a
    /// phone dials only the daemon, so one asked from here could never
    /// answer, while the push would still wake it
    pub async fn start_without_approvals(mut config: Config) -> Result<Self, AppError> {
        config.secrets.listen = None;
        config.secrets.phones.clear();

        Self::build(config, None, None, NO_APPROVAL_PAGE, Role::OneOff).await
    }

    async fn build(
        config: Config,
        notifier: Option<Arc<dyn Notifier>>,
        mac: Option<Arc<dyn Mac>>,
        unavailable: &'static str,
        role: Role,
    ) -> Result<Self, AppError> {
        let config = Arc::new(config);
        let state_dir = config.state_dir()?;
        let store = Store::open(&state_dir)?;
        let log = UsageLog::start(&state_dir, config.log_retention(), config.session_idle())?;
        let sealer = Sealer::load_or_create(&state_dir).map_err(ExecutorError::from)?;
        let passkeys = Arc::new(Passkeys::new(&config.public_origin(), store.clone())?);
        let session_store = store.clone();
        // the `logins` server types on the Mac whether or not approvals ask there
        let screen = mac.clone();
        let presence = mac.map(|mac| OnMac {
            mac,
            config: config.notify.mac.clone(),
        });
        // turning Mac notifications off stops approvals asking at the Mac,
        // not secret reads checking whether the owner is there
        let on_mac = presence.clone().filter(|_| config.notify.mac.enabled);
        // only the daemon sets trust up: a one-off run without the key trusts
        // nothing rather than whatever the config lists
        let trust = DeviceTrust::open(&state_dir, &config.secrets, role == Role::Daemon);
        let secrets = Secrets::new(
            &config.secrets,
            config.path().map(Path::to_owned),
            presence,
            Some(store.clone()),
            trust,
        );
        // before any upstream connects, so none asks for what the last
        // daemon already had
        // only by the daemon, which has bound its listeners by now: a one-off
        // run would use up what the next daemon is owed
        let handoff_keys = handoff::key_store(&state_dir, config.secrets.identity_file.is_none());
        let taken = match role {
            Role::Daemon => {
                secrets
                    .onepassword
                    .take_over(&state_dir, &handoff_keys, &config)
                    .await
            }
            Role::OneOff => Ok(TakenOver::default()),
        };
        match taken {
            Ok(taken) => {
                if !taken.values.is_empty() {
                    tracing::info!(
                        count = taken.values.len(),
                        "took over the last daemon's secrets"
                    );
                }
                if !taken.dropped.is_empty() {
                    tracing::warn!(
                        references = ?taken.dropped,
                        "a server using these changed since the last daemon; asking for them again"
                    );
                }
            }
            Err(error) => {
                tracing::warn!(%error, "could not use the last daemon's secrets; reading them again");
            }
        }
        let oauth = OAuth::new(&config, store.clone(), secrets.onepassword.clone());
        let approvals = Approvals::new(
            &config.public_base(),
            config.approvals.timeout(),
            notifier,
            on_mac.clone(),
            unavailable,
            store.clone(),
        );

        let executor = Arc::new(Executor::new(&config, sealer, store.clone()).await?);
        let gateway = Gateway::start(
            Arc::clone(&config),
            Arc::clone(&executor),
            approvals,
            log.clone(),
            UpstreamAccess {
                oauth,
                store: session_store.clone(),
                secrets,
                mac: screen,
            },
        );
        let executions = Arc::new(Executions::new(
            Arc::clone(&gateway),
            executor,
            config.limits.result_ttl(),
            config.limits.max_retained_result_bytes,
            session_store.clone(),
        ));

        let teardown = Arc::new(Teardown {
            gateway: Arc::clone(&gateway),
            executions: Arc::clone(&executions),
        });

        Ok(Self {
            _teardown: teardown,
            config,
            state_dir,
            role,
            gateway,
            executions,
            passkeys,
            store: session_store,
            log,
        })
    }

    /// Picks up what the previous process left in the database: parked
    /// executions resume, the others that were running become `interrupted`,
    /// admin actions wait for their approval again, and notifications that
    /// failed are sent again
    ///
    /// The daemon calls this once at boot, before it serves; one-off CLI
    /// runs do not, because they share the database with a running daemon
    pub fn recover(&self) {
        self.executions.recover();
        self.executions.start_housekeeping();

        let approvals = self.gateway.approvals();
        for (waiting, action) in approvals.restore_admin_actions() {
            attach_action(Arc::clone(&self.passkeys), waiting, action);
        }
        // after the restores above: a pending request nothing took up is
        // one whose execution did not survive
        approvals.abandon_orphans();
        approvals.renotify();

        // a phone opened after a restart finds the gateway before the next
        // read; one-off CLI runs never call this, so they never publish the
        // gateway's id alongside the daemon
        let companions = Arc::clone(self.gateway.companions());
        tokio::spawn(async move {
            if let Err(error) = companions.listen_for_phones().await {
                tracing::warn!(%error, "phones cannot reach this gateway until the next read");
            }
        });
    }

    /// Stops accepting executions and gives the running ones up to
    /// `limits.drain_secs` to finish; the ones waiting only on approvals are
    /// parked already and stay so for the next boot
    pub async fn drain(&self) {
        let interrupted = self.executions.drain(self.config.limits.drain()).await;
        if !interrupted.is_empty() {
            tracing::warn!(
                count = interrupted.len(),
                "executions still running after the drain were interrupted"
            );
        }
    }

    /// The last step of a stop: freezes durable state, so tearing the tasks
    /// down cannot withdraw approvals that parked executions wait on, and
    /// flushes the usage log
    pub async fn shutdown(&self) {
        self.halt();
        // a clean stop of the daemon only: a crash leaves nothing, and the
        // next daemon asks
        if self.role == Role::OneOff {
            self.gateway.companions().close().await;
            self.log.flush().await;

            return;
        }
        let keys = handoff::key_store(&self.state_dir, self.config.secrets.identity_file.is_none());
        // a read still waiting on a prompt holds the values; the stop does
        // not wait it out, and the next daemon asks instead
        let handing =
            self.gateway
                .secrets()
                .onepassword
                .hand_off(&self.state_dir, &keys, &self.config);
        let handed = tokio::time::timeout(HAND_OFF_WAIT, handing)
            .await
            .unwrap_or_else(|_| Err("a read was still in flight".to_owned()));
        match handed {
            Ok(0) => {}
            Ok(count) => tracing::info!(count, "handed this daemon's secrets to the next"),
            Err(error) => {
                tracing::warn!(%error, "could not hand off the secrets; the next daemon asks")
            }
        }
        // tells connected phones and frees `secrets.listen` for the next
        // process
        self.gateway.companions().close().await;
        self.log.flush().await;
    }

    /// Stops this app from writing durable state, as if the process had died
    ///
    /// Task teardown after a drain would otherwise withdraw the approvals of
    /// parked executions; tests use it to replace a daemon inside one process
    pub fn halt(&self) {
        self.gateway.approvals().freeze();
        self.executions.halt();
    }

    /// A guard that halts this app when it is dropped, however the owner
    /// leaves its scope; the app also halts once its last handle is gone, but
    /// tasks that still hold handles can keep that from happening in time
    pub fn freeze_on_drop(&self) -> FreezeOnDrop {
        FreezeOnDrop(self.clone())
    }

    /// The loaded configuration
    pub fn config(&self) -> &Arc<Config> {
        &self.config
    }

    /// Directory holding the database and snapshot key
    pub fn state_dir(&self) -> &PathBuf {
        &self.state_dir
    }

    /// Tool backend
    pub fn gateway(&self) -> &Arc<Gateway> {
        &self.gateway
    }

    /// Approval service
    pub fn approvals(&self) -> &Arc<Approvals> {
        self.gateway.approvals()
    }

    /// Enrolled passkeys and WebAuthn ceremonies
    pub fn passkeys(&self) -> &Arc<Passkeys> {
        &self.passkeys
    }

    /// Shared database handle, which also holds the app sessions
    pub fn store(&self) -> &Store {
        &self.store
    }

    /// Background execution registry
    pub fn executions(&self) -> &Arc<Executions> {
        &self.executions
    }

    /// Usage log
    pub fn usage(&self) -> &UsageLog {
        &self.log
    }
}
