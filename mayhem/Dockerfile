FROM swift:5.8-jammy as builder
ADD . /src
WORKDIR /src/mayhem
RUN swift build -c debug -Xswiftc -sanitize=fuzzer,address -Xswiftc -parse-as-library -Xcc -fsanitize=fuzzer-no-link,address

FROM swift:5.8-jammy-slim
COPY --from=builder /src/mayhem/.build/debug /debug
ENV ASAN_OPTIONS detect_leaks=0
ENTRYPOINT ["/debug/GEOFuzz"]
