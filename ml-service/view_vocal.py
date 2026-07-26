import pickle

# Đường dẫn đến file vocab của Đạt
vocab_path = 'vocab.pkl'

try:
    with open(vocab_path, 'rb') as f:
        vocab = pickle.load(f)
    
    print(f"📊 Tổng số từ vựng (Unigrams + Bigrams): {len(vocab)}")
    print("-" * 40)
    
    # In ra 20 mục đầu tiên để kiểm tra
    for i, (word, index) in enumerate(vocab.items()):
        print(f"{index}: {word}")
        if i > 20: 
            print("...")
            break
            
except FileNotFoundError:
    print("❌ Không tìm thấy file vocab.pkl. Bạn cần chạy baseline hoặc script tạo vocab trước!")
