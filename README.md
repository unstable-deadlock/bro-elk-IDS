Install Ubuntu 14.04 LTS Server
===============================

Download Ubuntu server 14.04 LTS
http://releases.ubuntu.com/14.04.3/ubuntu-14.04.3-server-amd64.iso
	* make user ids, password ids
	* make two network interfaces: 
		* monitor: one NAT with host, make sure it has this MAC "00:0c:29:bf:54:51"
		* manager: one VMnet for management, make sure it has this MAC "00:0c:29:bf:54:5b"
	* make new user: ids,ids
	* do not encrypt home directory
	* Select OpenSSH server for addition

Update/upgrade all packages
  	sudo apt-get update -q -y # Ignore the errors about having the cdrom loaded
  	sudo apt-get upgrade -q -y 
  	sudo apt-get install --no-install-recommends ubuntu-desktop -q -y
  	sudo reboot
  	// Ctrl-Alt-F2 to login on terminal
  	sudo apt-get install open-vm-tools-desktop gnome-terminal unity-lens-applications unity-lens-files -q -y

Reboot.

Remove guest login
    sudo bash -c 'cat > /usr/share/lightdm/lightdm.conf.d/50-ubuntu.conf <<EOL
    [SeatDefaults]
    user-session=ubuntu
    allow-guest=false
    EOL'
    	
    ## Add nsm group 
    sudo addgroup --system nsm
    ### Setup .vimrc
    cat > ~/.vimrc << EOL
    set nocompatible                       
    filetype off                                   
    filetype plugin indent on                                      
    autocmd! bufwritepost .vimrc source %                                           
    autocmd BufWritePre *.* :%s/\s\+$//e                                            
    set bs=2                                                                        
    autocmd ColorScheme * highlight ExtraWhitespace ctermbg=red guibg=red           
    au InsertLeave * match ExtraWhitespace /\s\+$/                                  
    syntax on                                                                       
    set nocompatible                                                                
    set nocp                                                                        
    set nonumber                                                                    
    set tw=79                                                                       
    set nowrap                                                                      
    set fo-=t                                                                       
    set colorcolumn=80                                                              
    set norelativenumber                                                            
    "au FocusLost * :set number                                                     
    "au FocusGained * :set relativenumber                                           
    set t_Co=256                                                                    
    color desert                                                                    
    highlight ColorColumn ctermbg=red                                               
    highlight LineNr ctermfg=235                                                    
    set tabstop=4                                                                   
    set softtabstop=4                                                               
    set shiftwidth=4                                                                
    set shiftround                                                                  
    set expandtab                                                                   
    set hlsearch                                                                    
    set incsearch                                                                   
    set ignorecase                                                                  
    set smartcase
    EOL

    ### Setup .bashrc
    cat > ~/.bashrc << EOL
    # ~/.bashrc: executed by bash(1) for non-login shells.
    # If not running interactively, don't do anything
    case $- in
        *i*) ;;
          *) return;;
    esac
    # don't put duplicate lines or lines starting with space in the history.
    # See bash(1) for more options
    HISTCONTROL=ignoreboth
    # append to the history file, don't overwrite it
    shopt -s histappend
    # for setting history length see HISTSIZE and HISTFILESIZE in bash(1)
    HISTSIZE=1000
    HISTFILESIZE=2000
    # check the window size after each command and, if necessary,
    # update the values of LINES and COLUMNS.
    shopt -s checkwinsize
    export PS1='\[\e[01;30m\]\t`if [ $? = 0 ]; then echo "\[\e[32m\] ✔ "; else echo "\[\e[31m\] ✘ "; fi`\[\e[00;37m\]\u\[\e[01;37m\]:\[\e[01;34m\]\w\[\e[00m\]\$ '
    alias ls='ls --color=auto'
    alias la='ls -al --color=auto'
    # Alias definitions.
    # You may want to put all your additions into a separate file like
    # ~/.bash_aliases, instead of adding them here directly.
    # See /usr/share/doc/bash-doc/examples in the bash-doc package.
    if [ -f ~/.bash_aliases ]; then
        . ~/.bash_aliases
    fi
    # enable programmable completion features (you don't need to enable
    # this, if it's already enabled in /etc/bash.bashrc and /etc/profile
    # sources /etc/bash.bashrc).
    if ! shopt -oq posix; then
      if [ -f /usr/share/bash-completion/bash_completion ]; then
        . /usr/share/bash-completion/bash_completion
      elif [ -f /etc/bash_completion ]; then
        . /etc/bash_completion
      fi
    fi
    EOL

Setup network
-------------

Rename the interfaces, monitor for the tap, manager for access to the config/apache
    sudo bash -c 'cat > /etc/udev/rules.d/70-persistent-net.rules <<EOL
    SUBSYSTEM=="net", ACTION=="add", DRIVERS=="?*", ATTR{dev_id}=="0x0", ATTR{type}=="1", ATTR{address}=="00:0c:29:bf:54:5b", KERNEL=="eth?", NAME="monitor"
    SUBSYSTEM=="net", ACTION=="add", DRIVERS=="?*", ATTR{dev_id}=="0x0", ATTR{type}=="1", ATTR{address}=="00:0c:29:bf:54:51", KERNEL=="eth?", NAME="manager"
    EOL'	

Setup the interfaces properly
    sudo bash -c 'cat > /etc/udev/rules.d/70-persistent-net.rules <<EOL

The loopback network interface
    auto lo
    iface lo inet loopback

The manager network interface
    auto manager 
    iface manager inet dhcp

The monitor network interface
    auto monitor 
    iface monitor inet manual
    	up ifconfig monitor up promisc
    	down ifconfig monitor down -promisc
    EOL'

Eliminate system swappiness to prevent stuff from being swapped out
    sudo bash -c "echo 'vm.swappiness = 0' >> /etc/sysctl.conf"
	
Install Bro 2.4.1
===============================

Install Dependencies
    sudo apt-get install cmake make git gcc g++ flex bison libpcap-dev libssl-dev python-dev swig zlib1g-dev git libcurl4-gnutls-dev -q -y

Download and install Bro
    cd ~
    git clone --recursive git://git.bro.org/bro
    cd bro
    ./configure --disable-broker --prefix=/nsm/bro && make && sudo make install
    rm ~/bro* -rf

Add the capability for Bro to output directly to elasticsearch
    cd ~
    git clone https://github.com/bro/bro-plugins
    cd bro-plugins
    ./configure --bro-dist=/home/ids/bro && make && make install

Double check that the plugin is active
    /nsm/bro/bin/bro -N Bro::ElasticSearch

Add bro user
    sudo adduser --system --ingroup nsm --home /nsm/bro --shell /sbin/nologin bro
    sudo usermod -a -G syslog bro
    sudo chown bro.nsm /nsm/bro -R

Allow 'bro' to capture off the interface
    sudo setcap cap_net_raw,cap_net_admin=eip /nsm/bro/bin/bro

Make a script that runs bro with upstart	(Brutally hacky, but if someone else has a better idea, let me know)
Copy and paste all lines below:
    sudo -u bro bash -c 'cat > /nsm/bro/bin/start.sh <<EOL
    #!/bin/bash

    while true; do
    		sleep 10
            case "$(pidof bro | wc -w)" in
            0) exit
               ;;
            1) exit
               ;;
            2) sleep 60
               ;;
            *) exit
               ;;
            esac
    done
    EOL'

Make the script executable
    sudo -u bro chmod 755 /nsm/bro/bin/start.sh
	
Add the startup job to upstart
    sudo bash -c 'cat > /etc/init/bro.conf <<EOL
    #!upstart                                                                       
    description "Bro Service"                                                       
    author "Blake Mackey"                                                           
                                                                                    
    start on runlevel []                                                            
    stop on runlevel []                                                             
                                                                                    
    respawn                                                                         
    pre-start script                                                                
        ethtool -K manager gro off gso off rx off tx off                    
        ethtool -K monitor gro off gso off rx off tx off                                           
        sudo -u bro /nsm/bro/bin/broctl start                                       
    end script                                                                      
                                                                                    
    exec sudo -u bro /nsm/bro/bin/start.sh                                          
                                                                                    
    pre-stop exec sudo -u bro /nsm/bro/bin/broctl stop
    EOL'

Make sure bro extracts files!
    sudo -u bro cat >> /nsm/bro/share/bro/site/local.bro <<EOL
    @load frameworks/files/extract-all-files.bro
    redef ignore_checksums = T;
    # Change the defaults in the plugin below and uncomment it to enable direct logging to elasticsearch
    #@load Bro/ElasticSearch/logs-to-elasticsearch.bro
    EOL

ELK stack install (plus Java 8)
===============================

Install Java 8
    sudo add-apt-repository -y ppa:webupd8team/java
    sudo apt-get update -y
    sudo apt-get install oracle-java8-installer -y

Install Logstash
-------------
    cd ~
    wget https://download.elastic.co/logstash/logstash/logstash-2.1.1.tar.gz
    tar xzvf logstash-2.1.1.tar.gz 
    sudo mkdir /nsm/logstash
    sudo mv logstash-2.1.1/* /nsm/logstash/
    rm ~/logstash* -rf

    ### Add logstash user
    sudo adduser --system --ingroup nsm --home /nsm/logstash --shell /sbin/nologin logstash
    sudo usermod -a -G syslog logstash
    sudo chown logstash.nsm /nsm/logstash -R

    ### Verify 
    ####add a new config
    sudo -u logstash mkdir /nsm/logstash/config
    sudo -u logstash mkdir /nsm/logstash/config/debug
    sudo -u logstash bash -c 'cat > /nsm/logstash/config/debug.conf <<EOL
    input { stdin { } }

    filter {
      grok {
        match => { "message" => "%{COMBINEDAPACHELOG}" }
      }
      date {
        match => [ "timestamp" , "dd/MMM/yyyy:HH:mm:ss Z" ]
      }
    }

    output {
      stdout { codec => rubydebug }
    }
    EOL'

Test out the config
    sudo -u logstash /nsm/logstash/bin/logstash -f /nsm/logstash/config/debug.conf

Paste the following into the terminal to simulate an apache log
    127.0.0.1 - - [11/Dec/2013:00:01:45 -0800] "GET /xampp/status.php HTTP/1.1" 200 3891 "http://cadenza/xampp/navi.php" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.9; rv:25.0) Gecko/20100101 Firefox/25.0"

Create logstash service to be called when wanting to listen out on the tap
    sudo bash -c 'cat > /etc/init/logstash.conf <<EOL
    #!upstart
    description "Logstash Service"
    author "Blake Mackey"

    start on runlevel []
    stop on runlevel []

    setgid nsm
    setuid logstash

    respawn

    exec /nsm/logstash/bin/logstash -f /nsm/logstash/config/
    EOL'

Install Elasticsearch
-------------

Download and unpack
    cd ~
    wget https://download.elasticsearch.org/elasticsearch/release/org/elasticsearch/distribution/tar/elasticsearch/2.1.1/elasticsearch-2.1.1.tar.gz
    tar xvzf elasticsearch-2.1.1.tar.gz
    sudo mkdir /nsm/elasticsearch
    sudo mv ~/elasticsearch-2.1.1/* /nsm/elasticsearch/
    rm ~/elasticsearch* -rf

Add elasticsearch user
    sudo adduser --system --ingroup nsm --home /nsm/elasticsearch --shell /sbin/nologin elasticsearch
    sudo usermod -a -G syslog elasticsearch
    sudo chown elasticsearch.nsm /nsm/elasticsearch -R

Create elasticsearch job to ensure elasticsearch is always running
    sudo bash -c 'cat > /etc/init/elasticsearch.conf <<EOL
    #!upstart
    description "elasticsearch Service"
    author "Blake Mackey"

    start on (local-filesystems and net-device-up IFACE=manager)
    stop on [!12345]

    setgid nsm
    setuid elasticsearch

    respawn
    exec /nsm/elasticsearch/bin/elasticsearch
    EOL'

Install Kibana
-------------

Download and unpack
    cd ~
    wget https://download.elastic.co/kibana/kibana/kibana-4.3.1-linux-x64.tar.gz
    tar xvzf kibana-4.3.1-linux-x64.tar.gz
    sudo mkdir /nsm/kibana
    sudo mv ~/kibana-4.3.1-linux-x64/* /nsm/kibana/
    rm ~/kibana* -rf

Add kibana user
    sudo adduser --system --ingroup nsm --home /nsm/kibana --shell /sbin/nologin kibana
    sudo usermod -a -G syslog kibana
    sudo chown kibana.nsm /nsm/kibana -R

Create kibana job to ensure kibana is always running
    sudo bash -c 'cat > /etc/init/kibana.conf <<EOL
    #!upstart
    description "Kibana Service"
    author "Blake Mackey"

    start on (local-filesystems and net-device-up IFACE=manager)
    stop on [!12345]

    setgid nsm
    setuid kibana

    respawn

    exec /nsm/kibana/bin/kibana
    EOL'

Make sure the paths are set
    sudo vim /etc/environment # add /nsm/bro/bin to PATH
