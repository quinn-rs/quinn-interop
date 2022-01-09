# -*- mode: ruby -*-
# vi: set ft=ruby :

Vagrant.configure("2") do |config|
  config.vm.box = "debian/bullseye64"

  config.vm.provider :libvirt do |domain|
    domain.memory = 8192
    domain.cpus = 8
  end

  config.vm.synced_folder ".", "/vagrant", type: "rsync", rsync__exclude: [ ".git/", "h3/target", "quinn-interop/target" ]
  config.vm.disk :disk, size: "100GB", primary: true

  config.vm.provision "shell", inline: <<-SHELL
    apt-get update
    echo "wireshark-common wireshark-common/install-setuid boolean true" | sudo debconf-set-selections
    DEBIAN_FRONTEND=noninteractive apt-get install -yq \
        curl \
        docker \
        docker-compose \
        python3 \
        python3-pip \
        git\
        wireshark \
        tshark
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y

    usermod -aG docker vagrant

    modprobe ip6table_filter
    echo ip6table_filter >> /etc/modules

    cd /vagrant/quic-interop-runner && pip3 install -r requirements.txt

    echo "cd /vagrant/quic-interop-runner" >> /home/vagrant/.bashrc

    if grep patch.crates.io /vagrant/h3/h3-quinn/Cargo.toml;then
      cat cargo_patch.toml >> /vagrant/h3/h3-quinn/Cargo.toml
    fi
  SHELL
end
