# cas-go

**cas-go** is a **Centralized Authentication Service (CAS)** built with **Go**, **MySQL**, and **Redis**.  
It provides a secure, scalable, and easy-to-deploy authentication service for managing user access across multiple applications.

---

## 🚀 Features

- ✅ **Centralized Authentication** — single sign-on (SSO) for multiple services  
- ✅ **User Registration** — built-in account registration flow  
- ✅ **OAuth Login** — supports login via third-party providers (e.g., Google, Facebook, Discord etc.)  
- ✅ **Two-Factor Authentication (2FA)** — supports email-based OTP and token-based verification  
- ✅ **Service Registry** — secure way to register and manage services
- ✅ **Session Management** — cookie-based session handling  

---


## 🧩 Getting Started

### 1. Clone the repository
```bash
git clone https://github.com/khanghh/cas-go.git
cd cas-go
```
### 2. Copy and edit the configuration
```bash
cp config.example.yaml config.yaml
```

Then edit config.yaml to match your environment (database, Redis, ports, etc).

### 3. Setup dependencies and build
Make sure you have Go, MySQL, and Redis installed.

Install Go dependencies:
```bash
go mod tidy
make
```

## ⚙️ Configuration
Edit the config.yaml file to define:

```yaml
debug: false
baseURL: http://localhost:3000
listenAddr : ":3000" 
staticDir: "./static"
templateDir: "./templates"
allowOrigins: 
 - http://localhost:8080

session:
  sessionMaxAge: "24h"
  cookieName: "sid"
  cookieSecure: false
  cookieHttpOnly: true

redisURL: redis://default:123456@localhost:6379/0

mysql:
  dsn: user:password@tcp(localhost:3306)/cas?charset=utf8mb4&parseTime=True&loc=Local
  maxIdleConns: 10
  maxOpenConns: 10
  connMaxIdleTime: 10
  connMaxLifetime: 10

authProviders: 
  oauth:
    google:
      clientId: xxxxxxxxxxxx-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx.apps.googleusercontent.com
      clientSecret: xxxxxx-xxxxxxxxxxxxxxxxxxxxxxxxxxxx
    discord:
      clientId: xxxxxxx
      clientSecret: xxxxxx

mail:
  backend: smtp
  smtp:
    host: smtp.example.com
    port: 587
    username: admin@example.com
    password: password
    from: noreply@example.com
    tls: true
    certFile: "./cert.pem"
    keyFile: "./keypem"
    caFile: "./ca.pem"

```

## 🖥️ Screenshots
### Login
<p float="left">
  <img src="https://github.com/khanghh/cas-go/blob/screenshots/login.png?raw=true" width="45%"> 
  <img src="https://github.com/khanghh/cas-go/blob/screenshots/home.png?raw=true" width="45%"> 
</p>

### Two Factor Authentication
<p float="left">
  <img src="https://github.com/khanghh/cas-go/blob/screenshots/select-2fa.png?raw=true" width="45%"> 
  <img src="https://github.com/khanghh/cas-go/blob/screenshots/otp-challenge.png?raw=true" width="45%"> 
  <img src="https://github.com/khanghh/cas-go/blob/screenshots/otp-email.png?raw=true" width="45%"> 
</p>

### Regsiter
<p float="left">
  <img src="https://github.com/khanghh/cas-go/blob/screenshots/register.png?raw=true" width="45%"> 
  <img src="https://github.com/khanghh/cas-go/blob/screenshots/verify-email.png?raw=true" width="45%"> 
</p>

<p float="left">
  <img src="https://github.com/khanghh/cas-go/blob/screenshots/registration-email.png?raw=true" width="45%"> 
  <img src="https://github.com/khanghh/cas-go/blob/screenshots/verify-email-success.png?raw=true" width="45%"> 
</p>

---

## 🛠️ Contributing

Pull requests are welcome!
For major changes, please open an issue first to discuss what you’d like to change.

**Bug Reports & Feature Requests**

Please use the issue tracker to report bugs or request new features.

## 📄 License

This project is licensed under the MIT License.
See the [LICENSE](LICENSE.txt) file for details.

## ❤️ Acknowledgements

- [Go](https://golang.org/)
- [MySQL](https://www.mysql.com/)
- [Redis](https://redis.io/)
