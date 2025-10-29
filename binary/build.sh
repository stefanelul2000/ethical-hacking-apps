echo "Building binary..."
g++ -std=c++20 -O0 -g main.cpp -o app -ldl
echo "Build complete"
echo "Run with: ./app"