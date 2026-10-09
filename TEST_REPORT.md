# รายงานผลการทดสอบ — Detect Demo (Tauri + React + TypeScript)

- **วันที่ทดสอบ:** 2026-10-10
- **สภาพแวดล้อม:** Windows 11 Home, bun, Rust/cargo 1.99.0 (stable-msvc), Vite 8.3.4, Tauri 2.12
- **ขอบเขต:** ตรวจ build/typecheck, ทดสอบ backend (Rust) ทุกคำสั่ง, ทดสอบเปิดแอปจริง

## 1. สรุปผล

| หัวข้อ | ผล | หมายเหตุ |
|---|---|---|
| ติดตั้ง dependency (`lucide-react`) | ผ่าน (หลังแก้) | อยู่ใน package.json แต่ไม่ได้ติดตั้ง → `bun add lucide-react` |
| `vite build` (frontend) | ผ่าน | 1,912 modules, JS 274.7 kB (gzip 84.6 kB) |
| `tsc --noEmit` | **ไม่ผ่าน (1 error)** | ดูข้อ 3.1 |
| `cargo check` (backend) | ผ่าน | ไม่มี warning |
| Rust unit/integration tests | ผ่าน 15/15 | เพิ่มโมดูล `tests` ใน `src-tauri/src/lib.rs` |
| เปิดแอปจริง (`tauri dev`) | ผ่าน | หน้าต่าง WebView2 ขึ้น, dev server ตอบ HTTP 200 |

> หมายเหตุ: การทดสอบ UI ด้วยการคลิกยังไม่ได้ทำแบบอัตโนมัติ (ตรวจได้เพียงว่าแอปเปิดและโหลดโมดูลได้) ควรทดสอบด้วยมืออีกรอบ

## 2. ผลทดสอบ Backend

### 2.1 `evaluate_custom_artifact` (ตรวจ artifact ที่ผู้ใช้ป้อน)

| กรณีทดสอบ | ผลลัพธ์ที่คาด | ผล |
|---|---|---|
| PowerShell `-enc` + IEX + DownloadString | High (≥3 rules) | ผ่าน |
| PowerShell `-ExecutionPolicy Bypass` อย่างเดียว | Medium | ผ่าน |
| PowerShell ปกติ (`Get-ChildItem`) | Low | ผ่าน |
| โดเมนผู้ขายโปรแกรมโกง (`auth.eulen.gg`) | High | ผ่าน |
| โดเมน TLD เสี่ยง (`example.ru`) | Medium | ผ่าน |
| โดเมนปกติ (`www.google.com`) | Low | ผ่าน |
| ไดรเวอร์ BYOVD (`gdrv.sys`) | High | ผ่าน |
| ไดรเวอร์ปกติ (`ntfs.sys`) | Low | ผ่าน |
| path ที่มีคำว่า `spoofer` | High | ผ่าน |
| `fsutil usn deletejournal` | High | ผ่าน |
| อินพุตว่าง / มีช่องว่างหน้าหลัง (trim) | Low / ตัดช่องว่างถูกต้อง | ผ่าน |

### 2.2 `run_forensic_scan` ทั้ง 17 โมดูล (สแกนเครื่องจริง, อ่านอย่างเดียว)

| โมดูล | เวลา (ms) | พบทั้งหมด | ถูกแฟล็ก |
|---|---:|---:|---:|
| autoruns-plus-plus | 2,165 | 16 | 1 |
| string-explorer-plus-plus | 241 | 4,727 | 0 |
| moss-2-0 | 310 | 1 | 0 |
| win-prefetch-view-plus-plus | 115 | 0 | 0 |
| usb-deview-plus-plus | 361 | 49 | 0 |
| saved-files-viewer-plus-plus | 378 | 0 | 0 |
| power-shell-parser-plus-plus | 112 | 809 | 18 |
| paths-parser-plus-plus | 120 | 70 | 23 |
| mft-explorer-plus-plus | 896 | 455 | 0 |
| kernel-live-dump-plus-plus | 388 | 305 | 0 |
| journal-trace-plus-plus | 362 | 10 | 0 |
| crashed-file-viewer-plus-plus | 108 | 10 | 0 |
| browsing-history-view-plus-plus | 5,643 | 20,316 | 0 |
| browser-downloads-view-plus-plus | 1,009 | 577 | 1 |
| bam-parser-plus-plus | 377 | 61 | 0 |
| amcache-parser-plus-plus | 484 | 135 | 0 |
| srum-explorer-plus-plus | 1,241 | 46 | 0 |

ทุกโมดูลคืนผล `Ok` ไม่ panic และ `tool_id` ตรงกับที่ขอ

### 2.3 `run_all_forensic_scans` (Full Audit)

- ใช้เวลา **12.6 วินาที**, สแกน 17 โมดูล, วิเคราะห์ 27,589 รายการ, แฟล็ก 43 รายการ
- ยอดรวมตรงกับผลรวมของแต่ละโมดูล (ผ่าน)

## 3. ปัญหาที่พบ

### 3.1 `tsc` ไม่ผ่าน — ทำให้ `bun run build` พัง (ควรแก้)
`src/components/ScanModal.tsx(11,3): error TS6133: 'Activity' is declared but its value is never read.`
สคริปต์ build คือ `tsc && vite build` จึงหยุดที่ `tsc` ทั้งที่ `vite build` ผ่าน
**แนวทางแก้:** ลบ `Activity` ออกจาก import ใน ScanModal.tsx

### 3.2 กฎตรวจจับใช้ substring จึงเกิด False Positive (ความเสี่ยงปานกลาง)
ผลทดสอบอินพุตปกติที่ถูกจัดเป็น High:

| ชนิด | อินพุตปกติ | ผล | คำที่ชน |
|---|---|---|---|
| driver_service | `genericaudio.sys` | High | `ene` (ใน gen**ene**ric… ) |
| file_path | `...\CCleaner\ccleaner.exe` | High | `cleaner` |
| powershell_cmd | `Where-Object {$_.Name -like 'wget*'}` | High | `wget` |

ผลคือโปรแกรมถูกกฎหมายอาจถูกแจ้งว่า "DETECTED - MALICIOUS" และคำแนะนำคือ "ban review"
**แนวทางแก้:** จับคู่แบบ word-boundary/ชื่อไฟล์ตรงตัว, ตัดคีย์เวิร์ดสั้น (`ene`, `esp`, `iwr`) หรือใช้ระดับ Medium แทน High สำหรับคีย์เวิร์ดกำกวม

### 3.3 ID เครื่องมือที่ไม่รู้จักถูกตอบว่า "สแกนสำเร็จ" (ความเสี่ยงต่ำ)
`run_forensic_scan("no-such-tool")` คืน `Ok` พร้อมข้อความ "Analyzed 306 records" เพราะตกไปที่ default branch แทนที่จะคืน error
**แนวทางแก้:** คืน `Err("Unknown tool id")` ใน default branch

### 3.4 ข้อสังเกตอื่น
- `browsing-history-view-plus-plus` ช้าที่สุด (5.6 วินาที / 20,316 รายการ) ควรพิจารณาจำกัดจำนวนหรือแบ่งหน้าใน UI
- `win-prefetch-view-plus-plus` และ `saved-files-viewer-plus-plus` ได้ 0 รายการ อาจเพราะไม่มีสิทธิ์ผู้ดูแลระบบ (Prefetch ต้องใช้ Admin) ควรแสดงข้อความเตือนสิทธิ์แทนการรายงานว่า "ไม่พบความผิดปกติ"
- `run_all_forensic_scans` รันโมดูลทีละตัวแบบอนุกรม และกลืน error (`if let Ok`) ทำให้โมดูลที่ล้มเหลวหายไปเงียบๆ

## 4. สิ่งที่เปลี่ยนในโปรเจกต์ระหว่างการทดสอบ

1. ติดตั้ง Rust toolchain (rustup) และถอน Docker Desktop (ตามที่ผู้ใช้สั่ง)
2. `bun add lucide-react` (ติดตั้ง v1.54.0)
3. เพิ่มโมดูล `#[cfg(test)] mod tests` ท้ายไฟล์ `src-tauri/src/lib.rs` (15 เทสต์)

## 5. วิธีรันซ้ำ

```powershell
bun install
bunx tsc --noEmit
bunx vite build
cd src-tauri
cargo test -- --nocapture --test-threads=1
cd ..
bun run tauri dev
```
