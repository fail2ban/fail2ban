Vagrant.configure("2") do |config|

    config.vm.define "secure" do |secure|
        secure.vm.box = "ubuntu/trusty64"
        secure.vm.hostname = "secure.dev.fail2ban.org"
        secure.vm.network "private_network", ip: "192.168.200.100"

#        secure.vm.synced_folder 'salt/roots', '/srv/salt'

#        secure.vm.provision :salt do |salt|
#            salt.minion_config = 'salt/minion'
#            salt.run_highstate = true
#            salt.verbose = true
#        end
    end

    config.vm.define "attacker" do |attacker|
        attacker.vm.box = "ubuntu/trusty64"
        attacker.vm.hostname = "attacker.dev.fail2ban.org"
        attacker.vm.network "private_network", ip: "192.168.200.150"

#        attacker.vm.synced_folder 'salt/roots', '/srv/salt'

#        attacker.vm.provision :salt do |salt|
#            salt.minion_config = 'salt/minion'
#            salt.run_highstate = true
#            salt.verbose = true
#        end
    end
end
