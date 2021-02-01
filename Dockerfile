FROM archlinux:latest

# faster mirrors
RUN echo 'Server = https://mirrors.kernel.org/archlinux/$repo/os/$arch' >  /etc/pacman.d/mirrorlist && \
    echo 'Server = https://mirrors.xtom.com/archlinux/$repo/os/$arch'   >> /etc/pacman.d/mirrorlist && \
    echo 'Server = https://mirror.lty.me/archlinux/$repo/os/$arch'      >> /etc/pacman.d/mirrorlist

# install bpftrace
RUN pacman -Syu --noconfirm bpftrace
