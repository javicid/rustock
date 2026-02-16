use super::*;
use k256::ecdsa::SigningKey;
use alloy_primitives::{B512, Bytes};
use std::sync::Arc;
use tokio::sync::Mutex;
use crate::discovery::message::{DiscoveryNode, DiscoveryPayload, DiscoveryPacket};

#[tokio::test]
async fn test_discovery_service_interaction() {
    let key1 = SigningKey::from_slice(&[0x01; 32]).unwrap();
    let id1 = B512::from_slice(&key1.verifying_key().to_encoded_point(false).as_bytes()[1..]);
    let table1 = Arc::new(Mutex::new(NodeTable::new(id1)));
    let local_node1 = DiscoveryNode {
        ip: Bytes::from(vec![127, 0, 0, 1]),
        udp_port: 0,
        tcp_port: 0,
        id: id1,
    };
    let service1 = Arc::new(
        DiscoveryService::new("127.0.0.1:0", key1, table1.clone(), 33, local_node1)
            .await
            .unwrap(),
    );
    let addr1 = service1.socket.local_addr().unwrap();

    let key2 = SigningKey::from_slice(&[0x02; 32]).unwrap();
    let id2 = B512::from_slice(&key2.verifying_key().to_encoded_point(false).as_bytes()[1..]);
    let table2 = Arc::new(Mutex::new(NodeTable::new(id2)));

    // Pre-populate table2 with a fake node so Neighbors will be non-empty
    let fake_id = B512::repeat_byte(0xAA);
    table2.lock().await.add_node(DiscoveryNode {
        ip: Bytes::from(vec![10, 0, 0, 1]),
        udp_port: 5050,
        tcp_port: 5050,
        id: fake_id,
    });

    let local_node2 = DiscoveryNode {
        ip: Bytes::from(vec![127, 0, 0, 1]),
        udp_port: 0,
        tcp_port: 0,
        id: id2,
    };
    let service2 = Arc::new(
        DiscoveryService::new("127.0.0.1:0", key2, table2.clone(), 33, local_node2)
            .await
            .unwrap(),
    );

    let mut buf = [0u8; 4096];

    // 1. Service 2 pings Service 1
    service2.send_ping(addr1).await.unwrap();

    // 2. Service 1 handles the ping → sends Pong, bonds, sends FindNode
    let (n, addr) = service1.socket.recv_from(&mut buf).await.unwrap();
    service1.handle_packet(&buf[..n], addr).await.unwrap();

    // Verify service 1 added service 2 to its table and bonded
    {
        let table = table1.lock().await;
        assert!(table.get_all_nodes().iter().any(|n| n.id == id2));
    }
    assert!(service1.bonded.lock().await.contains(&addr));

    // 3. Service 2 receives Pong
    let (n, addr) = service2.socket.recv_from(&mut buf).await.unwrap();
    let packet = DiscoveryPacket::decode(&buf[..n]).unwrap();
    assert!(matches!(packet.payload, DiscoveryPayload::Pong(_)));
    service2.handle_packet(&buf[..n], addr).await.unwrap();

    // 4. Service 2 receives FindNode (sent by service1 after bonding)
    let (n, addr) = service2.socket.recv_from(&mut buf).await.unwrap();
    let packet = DiscoveryPacket::decode(&buf[..n]).unwrap();
    assert!(
        matches!(packet.payload, DiscoveryPayload::FindNode(_)),
        "Expected FindNode, got {:?}",
        packet.payload
    );
    service2.handle_packet(&buf[..n], addr).await.unwrap();

    // 5. Service 1 receives Neighbors (from service2, containing the fake node)
    let (n, _addr) = service1.socket.recv_from(&mut buf).await.unwrap();
    let packet = DiscoveryPacket::decode(&buf[..n]).unwrap();
    if let DiscoveryPayload::Neighbors(nks) = &packet.payload {
        assert!(
            nks.nodes.iter().any(|n| n.id == fake_id),
            "Expected Neighbors to contain the fake node"
        );
    } else {
        panic!("Expected Neighbors, got {:?}", packet.payload);
    }

    // Verify service1 adds the neighbor to its table
    service1.handle_packet(&buf[..n], _addr).await.unwrap();
    {
        let table = table1.lock().await;
        assert!(
            table.get_all_nodes().iter().any(|n| n.id == fake_id),
            "Service 1 should have learned about the fake node via Neighbors"
        );
    }
}
