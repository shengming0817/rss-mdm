use super::pg::*;
use std::{sync::Arc, time::Duration};
pub struct AckProxy {
    pub port: u16,
    pub discard: Arc<std::sync::atomic::AtomicBool>,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for AckProxy {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl AckProxy {
    pub async fn start() -> Self {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let upstream = config()["port"].as_u64().unwrap() as u16;
        let discard = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flag = discard.clone();
        let task = tokio::spawn(async move {
            let mut connections = tokio::task::JoinSet::new();
            loop {
                tokio::select! {
                    accepted = listener.accept() => {
                        let (client, _) = accepted.unwrap();
                        let flag = flag.clone();
                        connections.spawn(async move {
                            let server = tokio::net::TcpStream::connect(("127.0.0.1", upstream)).await.unwrap();
                            let (mut cr, mut cw) = client.into_split();
                            let (mut sr, mut sw) = server.into_split();
                            let forward = tokio::io::copy(&mut cr, &mut sw);
                            let backward = async {
                                let mut buffer = [0; 16384];
                                loop {
                                    let n = sr.read(&mut buffer).await?;
                                    if n == 0 { return Ok::<(), std::io::Error>(()); }
                                    if !flag.load(std::sync::atomic::Ordering::SeqCst) {
                                        cw.write_all(&buffer[..n]).await?;
                                    }
                                }
                            };
                            tokio::select! { _ = forward => {}, _ = backward => {} }
                        });
                    }
                    _ = connections.join_next(), if !connections.is_empty() => {}
                }
            }
        });
        Self {
            port,
            discard,
            task,
        }
    }
}

pub struct CommitGate {
    holder: std::process::Child,
}
impl CommitGate {
    pub async fn start(id: &str) -> Self {
        sql(&format!(
            "CREATE FUNCTION public.hold_backend_commit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_advisory_xact_lock(238899); RETURN NEW; END $$; CREATE CONSTRAINT TRIGGER t2_hold_commit AFTER INSERT ON mdm_access.audit DEFERRABLE INITIALLY DEFERRED FOR EACH ROW WHEN (NEW.action='software_result' AND NEW.target='{id}') EXECUTE FUNCTION public.hold_backend_commit();"
        ));
        let c = config();
        let holder=std::process::Command::new("docker").args(["exec",c["container"].as_str().unwrap(),"psql","-At","-U","postgres","-d","backend","-c","SET application_name='backend_ack_holder'; SELECT pg_advisory_lock(238899); SELECT pg_sleep(30)"]).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null()).spawn().unwrap();
        wait_for(
            "SELECT count(*) FROM pg_locks WHERE locktype='advisory' AND objid=238899 AND granted",
        )
        .await;
        Self { holder }
    }
    pub async fn entered(&self) {
        wait_for("SELECT count(*) FROM pg_locks WHERE locktype='advisory' AND objid=238899 AND NOT granted").await;
    }
    pub fn release(&self) {
        sql(
            "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE application_name='backend_ack_holder'",
        );
    }
}
impl Drop for CommitGate {
    fn drop(&mut self) {
        let _ = self.holder.kill();
        let _ = self.holder.wait();
        sql(
            "DROP TRIGGER t2_hold_commit ON mdm_access.audit; DROP FUNCTION public.hold_backend_commit()",
        );
    }
}
async fn wait_for(q: &str) {
    tokio::time::timeout(Duration::from_secs(5), async {
        while sql(q) != "1" {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
}
