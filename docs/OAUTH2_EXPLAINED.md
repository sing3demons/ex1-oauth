# OAuth2 Flow Explanation (การอธิบาย OAuth2)

## 🏪 เปรียบเทียบง่ายๆ: OAuth2 เหมือนร้านสะดวกซื้อ

### ตัวละคร:
- **👤 คุณ** = Resource Owner (เจ้าของข้อมูล)
- **🛒 แอปสั่งอาหาร** = Client (แอปที่ต้องการข้อมูล)
- **🏦 ธนาคาร** = Authorization Server (ผู้ให้สิทธิ์)
- **💳 ระบบจ่ายเงิน** = Resource Server (ข้อมูลจริง)

### กระบวนการ:

#### 1️⃣ **คุณสั่งอาหารผ่านแอป**
```
แอป: "ต้องการเข้าถึงข้อมูลการจ่ายเงินของคุณ"
คุณ: "ตกลง ไปขอสิทธิ์ที่ธนาคารก่อน"
```
**ในโค้ด:**
```go
// client/main.go - initiateOAuth()
authURL := fmt.Sprintf("%s/oauth/authorize", serverURL)
ctx.Redirect(http.StatusFound, authURL)
```

#### 2️⃣ **คุณไปธนาคารเพื่อให้สิทธิ์**
```
ธนาคาร: "แอปสั่งอาหารต้องการดูยอดเงิน อนุญาตมั้ย?"
คุณ: "อนุญาต แต่ให้ดูได้แค่ยอดเงิน ห้ามถอนเงิน"
ธนาคาร: "นี่ใบอนุญาตชั่วคราว (authorization code) เอาไปให้แอป"
```
**ในโค้ด:**
```go
// main.go - authHandler.Authorize()
oauth2.GET("/authorize", authHandler.Authorize)
```

#### 3️⃣ **แอปเอาใบอนุญาตไปแลกบัตรเข้าถึง**
```
แอป: "นี่ใบอนุญาตจากลูกค้า ขอบัตรเข้าถึงข้อมูลหน่อย"
ธนาคาร: "นี่บัตรเข้าถึง (access token) ใช้ได้ 1 ชั่วโมง"
```
**ในโค้ด:**
```go
// main.go - authHandler.Token()
oauth2.POST("/token", authHandler.Token)
```

#### 4️⃣ **แอปใช้บัตรเข้าถึงข้อมูล**
```
แอป: "นี่บัตรเข้าถึง ขอดูข้อมูลลูกค้าหน่อย"
ระบบจ่ายเงิน: "ตรวจสอบบัตรแล้ว ถูกต้อง นี่ข้อมูลที่ขอ"
```
**ในโค้ด:**
```go
// บรรทัดที่คุณเลือก - main.go
oauth2.GET("/profile", authHandler.UserInfo)
```

## 🔒 ข้อดีของ OAuth2:

### ✅ **ปลอดภัย**
- แอปไม่ได้รหัสผ่านจริงของคุณ
- ได้แค่บัตรเข้าถึงชั่วคราว

### ✅ **ควบคุมได้**
- คุณเลือกได้ว่าจะให้สิทธิ์อะไรบ้าง
- สามารถเพิกถอนสิทธิ์ได้ตลอดเวลา

### ✅ **สะดวก**
- ไม่ต้องสร้างบัญชีใหม่ในทุกแอป
- ใช้บัญชีเดิมที่มีอยู่

## 🔄 OAuth2 Grant Types (ประเภทการขอสิทธิ์):

### 1. **Authorization Code** (ที่เราใช้)
- เหมาะสำหรับ web apps
- ปลอดภัยที่สุด

### 2. **Implicit**
- เหมาะสำหรับ mobile apps
- ได้ token โดยตรง

### 3. **Client Credentials**
- เหมาะสำหรับ server-to-server
- ไม่มีผู้ใช้เข้ามาเกี่ยวข้อง

### 4. **Password**
- ใช้ username/password โดยตรง
- เหมาะสำหรับ first-party apps

## 🛡️ Security Features ในโค้ดของเรา:

### **State Parameter**
```go
// client/main.go
state, err := generateState()
ctx.SetCookie("oauth_state", state, 600, "/", "", false, true)
```
- ป้องกัน CSRF attacks

### **JWT Tokens**
```go
// internal/services/oauth_service.go
token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
tokenString, err := token.SignedString([]byte(s.jwtSecret))
```
- Token ที่ไม่สามารถปลอมแปลงได้

### **Secure Cookie**
- httpOnly = true (ป้องกัน XSS)
- Secure = true (ใช้ได้แค่ HTTPS)

## 📊 Flow Diagram:

```
👤 User          🛒 Client App          🏦 Auth Server          💾 Resource Server
  |                    |                       |                        |
  |--- ขอเข้าใช้ ------>|                       |                        |
  |                    |--- ขอสิทธิ์ --------->|                        |
  |<--- redirect ------|                       |                        |
  |                    |                       |                        |
  |--- login/authorize ------------------------>|                        |
  |                    |                       |                        |
  |                    |<-- auth code ---------|                        |
  |                    |                       |                        |
  |                    |--- แลก token -------->|                        |
  |                    |<-- access token ------|                        |
  |                    |                       |                        |
  |                    |--- ขอข้อมูล (with token) ------------------>|
  |                    |<-- ข้อมูลผู้ใช้ ---------------------------|
  |<-- แสดงข้อมูล -----|                       |                        |
```

## 🎯 สรุป:
OAuth2 ช่วยให้แอปต่างๆ เข้าถึงข้อมูลของคุณได้อย่างปลอดภัย โดยไม่ต้องให้รหัสผ่านจริง และคุณสามารถควบคุมสิทธิ์การเข้าถึงได้เต็มที่!
