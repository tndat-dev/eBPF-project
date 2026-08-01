# Ethics and Safety

- Chỉ dùng attack simulation không phá hoại, namespace lab tách biệt và không
  mount service-account token.
- Không attach TLS uprobe toàn host; loader bắt buộc explicit PID trong scope.
- Plaintext chỉ pipe trong memory khi `--emit-payload` cho PID lab; không log,
  không persist, không đưa vào training snapshot.
- Không tự bật isolation/enforcement trong production từ candidate ML.
- Không đưa secrets, kubeconfig, password, private IP hoặc raw trace nhạy cảm
  vào artifact public. Dataset public chỉ chứa derived graph/features đã review.
- Mọi thử nghiệm phải có cleanup/rollback manifest và ghi rõ tác động workload.
