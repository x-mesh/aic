# frozen_string_literal: true

# Reference Homebrew formula for x-mesh/aic.
#
# Production copy lives in https://github.com/x-mesh/homebrew-tap (Formula/aic.rb).
# This file is the source of truth for that copy — keep them in sync when
# bumping versions or changing build commands.
#
# Why no `service do ... end` block:
#   `brew services` only integrates with macOS launchd; on Linux brew it is a
#   stub. We provide `aic daemon install` instead, which writes a launchd
#   plist on macOS and a systemd --user unit on Linux. One UX, both OSes.

class Aic < Formula
  desc "Shell command error analyzer with LLM (PTY wrapper + supervisor daemon)"
  homepage "https://github.com/x-mesh/aic"
  license "MIT"
  head "https://github.com/x-mesh/aic.git", branch: "main"

  # Replace with the actual release tag + sha256 when cutting a release.
  # `brew bump-formula-pr` automates this once the formula is in the tap.
  url "https://github.com/x-mesh/aic/archive/refs/tags/v0.3.0.tar.gz"
  sha256 "REPLACE_ME_WITH_RELEASE_TARBALL_SHA256"
  version "0.3.0"

  depends_on "rust" => :build

  def install
    # `cargo install --path` only installs binaries from that crate. The
    # workspace defines three binaries: `aic` (aic-client), `aic-session` and
    # `aicd` (both in aic-server). We install both crates so all three land
    # in #{bin}.
    system "cargo", "install", *std_cargo_args(path: "aic-client")
    system "cargo", "install", *std_cargo_args(path: "aic-server")
  end

  def caveats
    <<~EOS
      To run aicd in the background and on login:

        aic daemon install        # writes the right unit for your OS

      What this does:
        macOS  → ~/Library/LaunchAgents/com.x-mesh.aicd.plist (launchctl load)
        Linux  → ~/.config/systemd/user/aicd.service (systemctl --user enable --now)

      Sanity check:
        aic doctor                # PASS/WARN/FAIL across config / aicd / hooks / LLM

      First-time setup:
        aic config                # interactive provider/api_key/model wizard
        aic init zsh              # add `source ~/.aic/hooks.zsh` to your rc
    EOS
  end

  test do
    # All three binaries print a version. Keep these as the smoke test —
    # actually exercising aicd needs a writable HOME and is brittle in the
    # brew test sandbox.
    assert_match(/^aic /, shell_output("#{bin}/aic --version"))
    assert_match(/^aic-session /, shell_output("#{bin}/aic-session --version"))
    assert_match(/^aicd /, shell_output("#{bin}/aicd --version"))
  end
end
