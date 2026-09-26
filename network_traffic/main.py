import sys
from capture import PacketCapturer


def main():
    print("Network Traffic")

    bpf = input("Enter BPF filter: ").strip()
    capturer = PacketCapturer(bpf=bpf if bpf else None)

    try:
        count_input = input("Enter packet count to capture (default 50): ").strip()
        count = int(count_input) if count_input else 50

        capturer.start_capture(count=count)
    except KeyboardInterrupt:
        print("\nStopping...")
        capturer.stop()
        sys.exit(0)


if __name__ == "__main__":
    main()
    #  end process: taskkill /F /IM python.exe
