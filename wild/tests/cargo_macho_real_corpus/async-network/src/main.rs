use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

async fn loopback() -> std::io::Result<u32> {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
    let address = listener.local_addr()?;
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await?;
        let mut value = [0_u8; 1];
        socket.read_exact(&mut value).await?;
        socket.write_all(&[value[0] + 1]).await
    });
    let mut client = TcpStream::connect(address).await?;
    client.write_all(&[41]).await?;
    let mut answer = [0_u8; 1];
    client.read_exact(&mut answer).await?;
    server.await.unwrap()?;
    Ok(u32::from(answer[0]))
}

#[tokio::main]
async fn main() {
    assert_eq!(loopback().await.unwrap(), 42);
}

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn completes_loopback() {
        assert_eq!(super::loopback().await.unwrap(), 42);
    }
}
