use std::ffi::CStr;

use ivlan_rpc::Auth;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub async fn read_auth(mut r: impl AsyncRead + Unpin) -> std::io::Result<Auth> {
    let mut buf = [0; 61];
    r.read_exact(&mut buf[..4]).await?;

    match &buf[..4] {
        b"---:" => {
            r.read_exact(&mut buf[..60]).await?;
            Ok(Auth::None)
        }
        b"psw:" => {
            r.read_exact(&mut buf[..60]).await?;
            let cstr = CStr::from_bytes_until_nul(&buf).map_err(std::io::Error::other)?;
            let s = cstr.to_str().map_err(std::io::Error::other)?.to_owned();
            Ok(Auth::Password(s))
        }

        _ => Err(std::io::Error::other("Bad auth discriminant.")),
    }
}

pub async fn write_auth(auth: &Auth, mut w: impl AsyncWrite + Unpin) -> std::io::Result<()> {
    match auth {
        Auth::None => {
            w.write_all(b"---:").await?;
            w.write_all(&[0; 60]).await?;
        }
        Auth::Password(s) => {
            let pass_len = s.len();
            if pass_len > 60 {
                return Err(std::io::Error::other("Password longer than 60 bytes."));
            }

            w.write_all(b"psw:").await?;
            w.write_all(s.as_bytes()).await?;
            if pass_len < 60 {
                w.write_all(&[0; 60][..(60 - pass_len)]).await?;
            }
        }
    }

    Ok(())
}

#[derive(PartialEq)]
pub enum AuthResp {
    Ok,
    Bad,
}

pub async fn read_auth_resp(mut r: impl AsyncRead + Unpin) -> std::io::Result<AuthResp> {
    let mut buf = [0; 4];
    r.read_exact(&mut buf).await?;

    match &buf[..4] {
        b"ok--" => Ok(AuthResp::Ok),
        b"nok-" => Ok(AuthResp::Bad),

        _ => Err(std::io::Error::other("Bad auth response discriminant.")),
    }
}

pub async fn write_auth_resp(
    auth: &AuthResp,
    mut w: impl AsyncWrite + Unpin,
) -> std::io::Result<()> {
    w.write_all(match auth {
        AuthResp::Ok => b"ok--",
        AuthResp::Bad => b"nok-",
    })
    .await
}
