//! Wires configuration, state, approvals, gateway and executions into one handle

use std::{path::PathBuf, sync::Arc};

use crate::{
    approvals::{Approvals, NO_APPROVAL_PAGE, NO_NOTIFIER},
    config::{Config, ConfigError},
    executions::Executions,
    executor::{Executor, ExecutorError},
    gateway::Gateway,
    notify::{Notifier, Ntfy},
    oauth::OAuth,
    passkeys::{PasskeyError, Passkeys},
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

/// A running codemode instance; cheap to clone
#[derive(Clone)]
pub struct App {
    config: Arc<Config>,
    state_dir: PathBuf,
    gateway: Arc<Gateway>,
    executions: Arc<Executions>,
    passkeys: Arc<Passkeys>,
    log: UsageLog,
}

impl App {
    /// Starts state, upstream connections and the worker pool, notifying
    /// through the configured ntfy topic
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

        Self::start_with(config, notifier).await
    }

    /// Like [`App::start`] with a caller-supplied notifier; `None` refuses
    /// every `ask` call
    pub async fn start_with(
        config: Config,
        notifier: Option<Arc<dyn Notifier>>,
    ) -> Result<Self, AppError> {
        Self::build(config, notifier, NO_NOTIFIER).await
    }

    /// For one-off runs outside the daemon: nobody can reach an approval
    /// page, so `ask` calls are refused with a reason saying so
    pub async fn start_without_approvals(config: Config) -> Result<Self, AppError> {
        Self::build(config, None, NO_APPROVAL_PAGE).await
    }

    async fn build(
        config: Config,
        notifier: Option<Arc<dyn Notifier>>,
        unavailable: &'static str,
    ) -> Result<Self, AppError> {
        let config = Arc::new(config);
        let state_dir = config.state_dir()?;
        let store = Store::open(&state_dir)?;
        let log = UsageLog::start(&state_dir, config.log_retention())?;
        let sealer = Sealer::load_or_create(&state_dir).map_err(ExecutorError::from)?;
        let passkeys = Arc::new(Passkeys::new(&config.public_origin, store.clone())?);
        let oauth = OAuth::new(&config, store.clone());
        let approvals = Approvals::new(
            config.public_base(),
            config.approvals.timeout(),
            notifier,
            unavailable,
            store,
            log.clone(),
        );

        let executor = Arc::new(Executor::new(&config, sealer).await?);
        let gateway = Gateway::start(
            Arc::clone(&config),
            Arc::clone(&executor),
            approvals,
            log.clone(),
            oauth,
        );
        let executions = Arc::new(Executions::new(
            Arc::clone(&gateway),
            executor,
            config.limits.result_ttl(),
            config.limits.max_retained_result_bytes,
            log.clone(),
        ));

        Ok(Self {
            config,
            state_dir,
            gateway,
            executions,
            passkeys,
            log,
        })
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

    /// Background execution registry
    pub fn executions(&self) -> &Arc<Executions> {
        &self.executions
    }

    /// Usage log
    pub fn usage(&self) -> &UsageLog {
        &self.log
    }
}
