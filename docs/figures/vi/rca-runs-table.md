| Lượt | Attack có case riêng | Gộp sau case binary vô hại | Top-1 / top-3 | Preview → case p95 (s) | Case normal |
|---|---|---|---|---|---|
| pulse-stable-candidate | 86,7% (273/315) | 31 | 99,6% / 99,6% | 2,52 | 4765 |
| pulse-stable-refreshed | 86,7% (273/315) | 37 | 100,0% / 100,0% | 2,52 | 4867 |
| pulse-stable-confirm | 86,9% (456/525) | 56 | 99,8% / 99,8% | 2,50 | 3666 |
| pulse-peer-discount-confirm | 87,6% (459/524) | 44 | 99,8% / 100,0% | 2,59 | 575 |
| pulse-final-system-confirm | 89,3% (469/525) | 40 | 14,1% / 100,0% | 2,67 | 744 |

Top-1 / top-3: binary của fixture attack là nghi phạm hạng 1 / trong 3 hạng đầu (xếp hạng tính lại với baseline binary đóng băng, có luật hạ quyền lúc khởi chạy ở mọi lượt). Ở 4 lượt đầu, binary vô hại và binary attack dùng chung một đường dẫn, nên top-1 bị thổi phồng; lượt cuối chạy binary vô hại từ tên riêng (RCA 5.17). Lượt cuối dựng case từ cảnh báo Alertmanager đã giao, các lượt trước từ preview.
