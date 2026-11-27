class Guap < Formula
  desc "Pure-Rust single-machine offline AI and IT administration appliance federating 10 GUAP domain suites (326 MCP tools)"
  homepage "https://guap.ca/guap/"
  version "0.1.0"
  license "Apache-2.0"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/adpaolucci/guap/releases/download/v0.1.0/guap-aarch64-apple-darwin.tar.gz"
      sha256 "0000000000000000000000000000000000000000000000000000000000000000"
    else
      url "https://github.com/adpaolucci/guap/releases/download/v0.1.0/guap-x86_64-apple-darwin.tar.gz"
      sha256 "0000000000000000000000000000000000000000000000000000000000000000"
    end
  end

  on_linux do
    if Hardware::CPU.intel?
      url "https://github.com/adpaolucci/guap/releases/download/v0.1.0/guap-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "0000000000000000000000000000000000000000000000000000000000000000"
    end
  end

  def install
    bin.install "guap"
    bin.install "guap-iced"
    bin.install "guap-mcp"
    doc.install "README.md", "CHANGELOG.md"
    prefix.install "LICENSE", "NOTICE"
  end

  test do
    assert_match "guap", shell_output("#{bin}/guap --help")
    assert_match "guap-mcp", shell_output("#{bin}/guap-mcp --help")
    assert_match "guap-iced", shell_output("#{bin}/guap-iced --help")
  end
end
