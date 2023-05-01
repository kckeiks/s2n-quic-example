use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use futures::future::join_all;
use s2n_quic::client::Connect;
use s2n_quic::provider::tls;
use s2n_quic::{Client, Server};
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub fn criterion_benchmark(c: &mut Criterion) {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();

    let server_addr = "127.0.0.1:8989";
    let server_addr_clone = server_addr.clone();
    let content = &[0u8; 1024];
    let content_clone = content.clone();

    let (cert, key) = certificate();
    let tls_provider = TlsProvider { cert, key };
    let tls_provider_clone = tls_provider.clone();
    let server_task = runtime.spawn(async move {
        let mut server = Server::builder()
            .with_tls(tls_provider_clone)
            .unwrap()
            .with_io(server_addr_clone)
            .unwrap()
            .start()
            .unwrap();

        while let Some(mut conn) = server.accept().await {
            tokio::task::spawn(async move {
                loop {
                    match conn.accept_bidirectional_stream().await {
                        Ok(Some(mut stream)) => {
                            tokio::task::spawn(async move {
                                let mut buf = [0; 5];
                                stream.read(&mut buf).await.unwrap();
                                assert_eq!(&buf, b"hello");
                                stream.write(&content_clone).await.unwrap();
                            });
                        }
                        Ok(None) => break,
                        Err(s2n_quic::connection::Error::Closed { .. }) => break,
                        Err(e) => panic!("{e:?}"),
                    }
                }
            });
        }
    });

    let mut num_request = 1;
    while num_request <= 64 {
        c.bench_with_input(
            BenchmarkId::new(format!("{num_request} requests"), num_request),
            &num_request,
            |bencher, &size| {
                bencher.to_async(&runtime).iter(|| {
                    let tls_provider_clone = tls_provider.clone();
                    async move {
                        let mut tasks = vec![];
                        let client = Client::builder()
                            .with_tls(tls_provider_clone)
                            .unwrap()
                            .with_io("0.0.0.0:0")
                            .unwrap()
                            .start()
                            .unwrap();
                        let addr: SocketAddr = server_addr.parse().unwrap();
                        let mut connection = client
                            .connect(Connect::new(addr).with_server_name("localhost"))
                            .await
                            .unwrap();
                        for _ in 0..size {
                            let mut stream = connection.open_bidirectional_stream().await.unwrap();
                            let task = tokio::task::spawn(async move {
                                stream.write(b"hello").await.unwrap();
                                let mut buf = Vec::with_capacity(1024);
                                let n = stream.read_to_end(&mut buf).await.unwrap();
                                assert_eq!(n, 1024);
                            });
                            tasks.push(task);
                        }
                        join_all(tasks).await;
                    }
                })
            },
        );
        num_request *= 2;
    }
    server_task.abort();
}

pub fn certificate() -> (rustls::Certificate, rustls::PrivateKey) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let key = rustls::PrivateKey(cert.serialize_private_key_der());
    let cert = rustls::Certificate(cert.serialize_der().unwrap());
    (cert, key)
}

#[derive(Clone)]
pub struct TlsProvider {
    cert: rustls::Certificate,
    key: rustls::PrivateKey,
}

impl tls::Provider for TlsProvider {
    type Server = tls::rustls::Server;
    type Client = tls::rustls::Client;
    type Error = rustls::Error;

    fn start_server(self) -> Result<Self::Server, Self::Error> {
        let mut config = rustls::ServerConfig::builder()
            .with_safe_defaults()
            .with_no_client_auth()
            .with_single_cert(vec![self.cert], self.key)
            .unwrap();
        config.alpn_protocols = vec![b"prototest".to_vec()];
        Ok(config.into())
    }

    fn start_client(self) -> Result<Self::Client, Self::Error> {
        let mut roots = rustls::RootCertStore::empty();
        roots.add(&self.cert).unwrap();

        let mut config = rustls::ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(roots)
            .with_no_client_auth();
        config.alpn_protocols = vec![b"prototest".to_vec()];
        Ok(config.into())
    }
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
