# osc52

A simple client implemeting the OSC52 copy/paste protocol. Install with `cargo install osc52`.

I wrote this utility because all of the existing ones are hard-coded to use /dev/tty instead of allowing you to specify a TTY device. `osc52` allows you to specify a TTY using a command-line option or environment variable. This way, it can be called from within Neovim (which detaches child processes from the controlling TTY) with the help of a shell startup script to export the current TTY as an environment variable.
