# 🚀 Super LOG Server (Enterprise MikroTik Syslog & Traffic Monitoring)

রেফারেন্স ছবির হুবহু আদলে তৈরি একটি পূর্ণাঙ্গ আধুনিক **Super LOG Management System**।

---

## 🌐 কিভাবে চেক ও ব্যবহার করবেন?

সার্ভারটি বর্তমানে চালু রয়েছে! আপনার ব্রাউজার (Chrome, Edge, Firefox) ওপেন করে নিচের লিংকে প্রবেশ করুন:

👉 **[http://localhost:8000](http://localhost:8000)** (অথবা `http://127.0.0.1:8000`)

### 🔑 লগইন তথ্য (Credentials):
- **User Name:** `arif`
- **Password:** `admin123`

---

## 📌 মূল ফিচার ও ট্রাফিক রিপোর্ট ড্রিলডাউন:

### 1. 📊 4-Level Traffic Report Drilldown (ছবি অনুযায়ী হুবহু):
- **Level 1 (Yearly View):** `/traffic/report?user=mc@cmh023`
  - কলাম: `Date` (2026), `User`, `Upload` (178.8 GB), `Download` (2.5 TB), `Total` (2.7 TB)
- **Level 2 (Monthly View):** `/traffic/report?user=mc@cmh023&year=2026`
  - কলাম: `Date` (2026-07 থেকে 2026-11), `User`, `Upload`, `Download`, `Total`
- **Level 3 (Daily View):** `/traffic/report?user=mc@cmh023&year=2026&month=2026-11`
  - কলাম: `Date` (2026-11-01 থেকে 2026-11-11), `User`, `Upload`, `Download`, `Total`
- **Level 4 (Individual PPPoE Sessions):** `/traffic/report?user=mc@cmh023&date=2026-11-11`
  - কলাম: `SL`, `User`, `MAC`, `IP Address`, `Start Time`, `End Time` (লাইভ সেশনে সবুজ ব্যাজ `Connected`), `Online Time`, `Upload`, `Download`, `Total`, `Identity`, `Host`

### 2. 👥 Online Users (1,538+ Customers Synced):
- `/traffic/online-users` এ প্রতিটি ইউজারনেমে ক্লিক করলেই সরাসরি তার পূর্ণ ট্রাফিক রিপোর্ট ওপেন হবে।

### 3. 🌐 Modernized UI Theme:
- নতুন Sleek Dark Navy Sidebar (`Super LOG CORE v2.0`)
- Elevated Cards with Smooth Borders & High-contrast Badges
- Live Engine Status Indicator (`UDP 5514 Listening`)
- MikroTik RouterOS API Auto-sync & Pool Export Script Generator
