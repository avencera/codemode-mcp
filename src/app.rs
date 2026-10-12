//! Wires configuration, gateway and executions into one handle

use std::sync::Arc;

use crate::{
    config::Config,
    executions::Executions,
    executor::{Executor, ExecutorError},
    gateway::Gateway,
    policy::{Approver, NoApprover},
};

/// A running codemode instance; cheap to clone
#[derive(Clone)]
pub struct App {
    config: Arc<Config>,
    gateway: Arc<Gateway>,
    executions: Arc<Executions>,
}

impl App {
    /// Starts upstream connections and the worker pool
    ///
    /// Tools whose policy is `ask` are refused until an approval flow is
    /// supplied through [`App::start_with`]
    pub async fn start(config: Config) -> Result<Self, ExecutorError> {
        Self::start_with(config, Arc::new(NoApprover)).await
    }

    /// Like [`App::start`] with a caller-supplied approval flow
    pub async fn start_with(
        config: Config,
        approver: Arc<dyn Approver>,
    ) -> Result<Self, ExecutorError> {
        let config = Arc::new(config);
        let executor = Arc::new(Executor::new(&config).await?);
        let gateway = Gateway::start(Arc::clone(&config), Arc::clone(&executor), approver);
        let executions = Arc::new(Executions::new(
            Arc::clone(&gateway),
            executor,
            config.limits.result_ttl(),
            config.limits.max_retained_result_bytes,
        ));

        Ok(Self {
            config,
            gateway,
            executions,
        })
    }

    /// The loaded configuration
    pub fn config(&self) -> &Arc<Config> {
        &self.config
    }

    /// Tool backend
    pub fn gateway(&self) -> &Arc<Gateway> {
        &self.gateway
    }

    /// Background execution registry
    pub fn executions(&self) -> &Arc<Executions> {
        &self.executions
    }
}
