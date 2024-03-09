use color_eyre::eyre::{self, OptionExt};

use crate::{
    cert::{CaCredentials, ServerCredentials},
    config::{Config, Daemon},
    daemon::events::EventKind,
    utils,
};

use self::events::EventQueue;

mod events;

pub fn run_daemon_mode(config: Config<Daemon>) -> eyre::Result<()> {
    log::info!("Running in daemon mode");

    DaemonState::run(config)?;

    Ok(())
}

struct DaemonState {
    config: Config<Daemon>,
    event_queue: EventQueue,
    ca_credentials: CaCredentials,
    server_credentials: ServerCredentials,
}

impl DaemonState {
    fn run(config: Config<Daemon>) -> eyre::Result<()> {
        let ca_credentials = load_or_generate_ca_credentials(&config)?;
        let server_credentials = load_or_generate_server_credentials(&config, &ca_credentials)?;
        let mut event_queue = EventQueue::new();

        event_queue
            .schedule_renew_server(server_credentials.certificate(), config.renew_server_after)?;

        if let Some(renew_root_after) = config.renew_root_after {
            event_queue
                .schedule_renew_root(&ca_credentials.root_certificate(), renew_root_after)?;
        }

        let state = Self {
            config,
            event_queue,
            ca_credentials,
            server_credentials,
        };

        state.event_loop()
    }

    fn event_loop(mut self) -> eyre::Result<()> {
        loop {
            let event = self
                .event_queue
                .pop()
                .ok_or_eyre("Unexpected end of event queue")?;

            utils::sleep_until(event.scheduled_time);

            match event.kind {
                EventKind::RenewServerCredentials => self.handle_renew_server()?,
                EventKind::RenewCaCredentials => self.handle_renew_root()?,
            }
        }
    }

    fn handle_renew_server(&mut self) -> eyre::Result<()> {
        log::info!("Updating server's credentials");
        let new_credentials = ServerCredentials::generate(&self.config, &self.ca_credentials)?;
        new_credentials.save(&self.config)?;

        self.server_credentials = new_credentials;

        self.event_queue.schedule_renew_server(
            &self.server_credentials.certificate(),
            self.config.renew_server_after,
        )?;
        log::info!("Server's credentials updated successfully");

        Ok(())
    }

    fn handle_renew_root(&mut self) -> eyre::Result<()> {
        log::info!("Updating ASoCA's credentials and creating new server's credentials");

        let new_asoca_credentials = CaCredentials::generate(&self.config)?;
        let new_server_credentials =
            ServerCredentials::generate(&self.config, &new_asoca_credentials)?;

        new_asoca_credentials.save(&self.config)?;
        new_server_credentials.save(&self.config)?;

        // we need to reschedule updating server's certificate
        // since we already did it
        self.event_queue.clear();
        self.event_queue.schedule_renew_root(
            new_asoca_credentials.root_certificate(), 
            self.config.renew_root_after.expect("Should only renew root certificate when the feature is turned on. If you see this, there is a bug"))?;
            
        self.event_queue.schedule_renew_server(new_server_credentials.certificate(), self.config.renew_server_after)?;
        
        self.ca_credentials = new_asoca_credentials;
        self.server_credentials = new_server_credentials;

        log::info!("Credentials updated successfully");

        Ok(())
    }
}

fn load_or_generate_ca_credentials(config: &Config<Daemon>) -> eyre::Result<CaCredentials> {
    let load_result = CaCredentials::try_load(config)?;

    if let Some(ca_credentials) = load_result {
        return Ok(ca_credentials);
    }
    log::info!("Generating ASoCA's credentials");
    // update_ca_credentials(config)
    let ca_credentials = CaCredentials::generate(config)?;
    ca_credentials.save(config)?;

    Ok(ca_credentials)
}

fn load_or_generate_server_credentials(
    config: &Config<Daemon>,
    ca_credentials: &CaCredentials,
) -> eyre::Result<ServerCredentials> {
    let load_result = ServerCredentials::try_load(config, ca_credentials)?;

    if let Some(server_credentials) = load_result {
        return Ok(server_credentials);
    }
    
    log::info!("Generating server's credentials");
    let server_credentials = ServerCredentials::generate(&config, &ca_credentials)?;
    server_credentials.save(config)?;

    Ok(server_credentials)
}
