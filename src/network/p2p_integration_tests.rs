//! Prueba de humo para verificar que el `AdvancedP2PManager` se inicializa correctamente.

#[cfg(test)]
mod tests {
    use crate::network::{AdvancedP2PConfig, AdvancedP2PManager, KeyManager};

    #[tokio::test]
    async fn manager_starts_and_stops_cleanly() {
        let key_manager = KeyManager::generate().expect("failed to generate test key manager");
        let id = key_manager.kademlia_id();
        let manager = AdvancedP2PManager::new(AdvancedP2PConfig::default(), id);

        manager.start().await.expect("manager should start");
        manager.stop().await.expect("manager should stop");
    }
}
