How to install ELK Stack/Elastic Stack on Ubuntu 16.04 LTS Server
===============================

Install Ubuntu 16.04 LTS Server
===============================

Download Ubuntu server 16.04 LTS
http://releases.ubuntu.com/16.04/ubuntu-16.04.1-desktop-amd64.iso

* make user ids, password xxx
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

Ctrl-Alt-F2 to login on terminal.

    sudo apt-get install open-vm-tools-desktop gnome-terminal unity-lens-applications unity-lens-files indicator-session -q -y

Reboot.

Remove guest login

    sudo bash -c 'cat > /usr/share/lightdm/lightdm.conf.d/50-ubuntu.conf <<EOL
    [SeatDefaults]
    user-session=ubuntu
    allow-guest=false
    EOL'

Add nsm group

    sudo addgroup --system nsm

Setup .vimrc

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

Setup .bashrc

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

    sudo bash -c 'cat > /etc/network/interfaces <<EOL

    # The loopback network interface
    auto lo
    iface lo inet loopback

    # The manager network interface
    auto manager
    iface manager inet dhcp
        pre-up /sbin/ethtool -K manager rx off
        pre-up /sbin/ethtool -K manager tx off
        pre-up /sbin/ethtool -K manager sg off
        pre-up /sbin/ethtool -K manager tso off
        pre-up /sbin/ethtool -K manager ufo off
        pre-up /sbin/ethtool -K manager gso off
        pre-up /sbin/ethtool -K manager gro off
        pre-up /sbin/ethtool -K manager lro off

    # The monitor network interface
    auto monitor
    iface monitor inet manual
        pre-up /sbin/ethtool -K monitor rx off
        pre-up /sbin/ethtool -K monitor tx off
        pre-up /sbin/ethtool -K monitor sg off
        pre-up /sbin/ethtool -K monitor tso off
        pre-up /sbin/ethtool -K monitor ufo off
        pre-up /sbin/ethtool -K monitor gso off
        pre-up /sbin/ethtool -K monitor gro off
        pre-up /sbin/ethtool -K monitor lro off
        up ifconfig monitor up promisc
        down ifconfig monitor down -promisc
    EOL'

Eliminate system swappiness to prevent stuff from being swapped out

    sudo bash -c "echo 'vm.swappiness = 0' >> /etc/sysctl.conf"

Install Bro 2.5
===============================

Install Dependencies

    sudo apt-get install cmake make git gcc g++ flex bison libpcap-dev libssl-dev python-dev swig zlib1g-dev git libcurl4-gnutls-dev -q -y

Download and install Bro

    cd ~
    git clone --recursive git://git.bro.org/bro
    cd bro
    ./configure --disable-broker --prefix=/nsm/bro && make && sudo make install
    rm ~/bro* -rf

Add bro user

    sudo adduser --system --ingroup nsm --home /nsm/bro --shell /sbin/nologin bro
    sudo usermod -a -G syslog bro
    sudo chown bro.nsm /nsm/bro -R

Allow 'bro' to capture off the interface

    sudo setcap cap_net_raw,cap_net_admin=eip /nsm/bro/bin/bro

Make a script that runs bro with upstart    (Brutally hacky, but if someone else has a better idea, let me know)
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

Add the startup job to systemd

    sudo bash -c 'cat > /etc/systemd/system/bro.service <<EOL
    [Unit]
    Description=Bro Network Intrusion Detection System (NIDS)
    After=network.target

    [Service]
    User=bro
    Type=forking
    Environment=HOME=/
    ExecStart=/nsm/bro/bin/broctl start

    [Install]
    WantedBy=multi-user.target
    EOL'
    
Enable the Bro service
    
    sudo systemctl enable bro.service

Make sure bro extracts files!

    sudo -u bro cat >> /nsm/bro/share/bro/site/local.bro <<EOL
    @load frameworks/files/extract-all-files.bro
    redef ignore_checksums = T;
    # Change the defaults in the plugin below and uncomment it to enable direct logging to elasticsearch
    #@load Bro/ElasticSearch/logs-to-elasticsearch.bro
    EOL
    
Edit Bro configuration files to suit

    sudo -u bro vi /nsm/bro/etc/node.cfg
    
Deploy configuration files/check for errors (Do this every time after editing config files)

    sudo -u bro /nsm/bro/bin/broctl deploy

Elastic stack install (plus Java 8)
===============================

Install Java 8

    sudo add-apt-repository -y ppa:webupd8team/java
    sudo apt-get update -y
    sudo apt-get install oracle-java8-installer -y

Install Logstash 5.0.0-alpha5
-------------

Download logstash

    cd ~
    wget https://download.elastic.co/logstash/logstash/logstash-5.0.0-alpha5.tar.gz
    tar xzvf logstash-5.0.0-alpha5.tar.gz
    sudo mkdir /nsm/logstash
    sudo mv logstash-5.0.0-alpha5/* /nsm/logstash/
    rm ~/logstash* -rf

Add logstash user

    sudo adduser --system --ingroup nsm --home /nsm/logstash --shell /sbin/nologin logstash
    sudo usermod -a -G syslog logstash
    sudo chown logstash.nsm /nsm/logstash -R

Verify and add a new config

    sudo -u logstash mkdir /nsm/logstash/config
    sudo -u logstash mkdir /nsm/logstash/config/pipeline
    sudo -u logstash bash -c 'cat > /nsm/logstash/config/pipeline/debug.conf <<EOL
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

    sudo -u logstash /nsm/logstash/bin/logstash -f /nsm/logstash/config/pipeline/debug.conf

Paste the following into the terminal to simulate an apache log

    127.0.0.1 - - [11/Dec/2013:00:01:45 -0800] "GET /xampp/status.php HTTP/1.1" 200 3891 "http://cadenza/xampp/navi.php" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.9; rv:25.0) Gecko/20100101 Firefox/25.0"

You should see the following output

    {
            "request" => "/xampp/status.php",
              "agent" => "\"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.9; rv:25.0) Gecko/20100101 Firefox/25.0\"",
               "auth" => "-",
              "ident" => "-",
               "verb" => "GET",
            "message" => "127.0.0.1 - - [11/Dec/2013:00:01:45 -0800] \"GET /xampp/status.php HTTP/1.1\" 200 3891 \"http://cadenza/xampp/navi.php\" \"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.9; rv:25.0) Gecko/20100101 Firefox/25.0\"",
           "referrer" => "\"http://cadenza/xampp/navi.php\"",
         "@timestamp" => 2013-12-11T08:01:45.000Z,
           "response" => "200",
              "bytes" => "3891",
           "clientip" => "127.0.0.1",
           "@version" => "1",
               "host" => "anon",
        "httpversion" => "1.1",
          "timestamp" => "11/Dec/2013:00:01:45 -0800"
    }


    
Edit the logstash config to load all configurations placed in pipeline directory

    sudo vim /nsm/logstash/config/logstash.yml
    # path.config: /nsm/logstash/config/pipeline                                      

Edit the /nsm/logstash/config/startup.options so that logstash can generate the correct logstash.service file.

    sudo vim /nsm/logstash/config/startup.options
    # Change LS_HOME=/nsm/logstash

Generate the logstash.service file and enable it

    sudo /nsm/logstash/bin/system-install
    sudo systemctl start logstash
    sudo systemctl enable logstash.service

Add the Bro input gem to the logstash Gemfile in order to automatically parse Bro logs...no regex required.

    echo 'gem "logstash-input-bro", :github => "BrashEndeavours/logstash-input-bro"' >> /nsm/logstash/Gemfile

Update the installed plugins.

    /nsm/logstash/bin/logstash-plugin install --no-verify

Should result in...

    Installing...
    Installation successful

Now to use this inside the logstash config file....

Note 1: There has to be a bro entry like below for each expected file log.  They dont have to always exist. This plugin will watch the filesystem, and grab the log when it is created. It will also parse out field types and format them correctly.

Note 2: the sincedb is set to null for testing, so that every time it runs, logstash pulls all the entries out. If you want a tail behaviour, set this to something non-null.

##### Sample.conf

    input {
        bro {
            type => "conn"
            path => "/path_to/conn.log"
            start_position => "beginning"
            sincedb_path => "/dev/null"
        }
    }
    output {
    #   stdout { codec => rubydebug }
        elasticsearch {
          hosts => ["127.0.0.1:9200"]
        }
    }

Save the logstash_bro.conf below into /nsm/logstash/etc/

Install Elasticsearch 5.0.0-alpha5
-------------

Download and unpack

    cd ~
    wget https://download.elastic.co/elasticsearch/release/org/elasticsearch/distribution/tar/elasticsearch/5.0.0-alpha5/elasticsearch-5.0.0-alpha5.tar.gz
    tar xvzf elasticsearch-5.0.0-alpha5.tar.gz
    sudo mkdir /nsm/elasticsearch
    sudo mv ~/elasticsearch-5.0.0-alpha5/* /nsm/elasticsearch/
    rm ~/elasticsearch* -rf

Add elasticsearch user

    sudo adduser --system --ingroup nsm --home /nsm/elasticsearch --shell /sbin/nologin elasticsearch
    sudo usermod -a -G syslog elasticsearch
    sudo chown elasticsearch.nsm /nsm/elasticsearch -R

Edit /nsm/elasticsearch/config/elasticsearch.yml to set:

    # Set the bind address to a specific IP (IPv4 or IPv6):
    network.host: 127.0.0.1
    # Set a custom port for HTTP:
    http.port: 9200

Create directories needed by SystemD

    sudo mkdir /var/log /var/log/elasticsearch
    sudo mkdir /var/lib /var/lib/elasticsearch

    sudo chown elasticsearch.nsm /var/log/elasticsearch /var/lib/elasticsearch
    
Create elasticsearch job to ensure elasticsearch is always running

    sudo bash -c 'cat > /etc/systemd/system/elasticsearch.service <<EOL
    [Unit]
    Description=Elasticsearch
    After=network.target

    [Service]
    WorkingDirectory=/nsm/elasticsearch
    User=elasticsearch

    ExecStart=/nsm/elasticsearch/bin/elasticsearch -Edefault.path.logs=/var/log/elasticsearch -Edefault.path.data=/var/lib/elasticsearch -Edefault.path.conf=/nsm/elasticsearch/config

    StandardOutput=journal
    StandardError=inherit

    # Specifies the maximum file descriptor number that can be opened by this process
    LimitNOFILE=65536

    # Specifies the maximum number of bytes of memory that may be locked into RAM
    # Set to "infinity" if you use the "bootstrap.memory_lock: true" option
    # in elasticsearch.yml and "MAX_LOCKED_MEMORY=unlimited" in /etc/sysconfig/elasticsearch
    #LimitMEMLOCK=infinity

    # Disable timeout logic and wait until process is stopped
    TimeoutStopSec=0

    # SIGTERM signal is used to stop the Java process
    KillSignal=SIGTERM

    # Java process is never killed
    SendSIGKILL=no

    # When a JVM receives a SIGTERM signal it exits with code 143
    SuccessExitStatus=143

    [Install]
    WantedBy=multi-user.target
    EOL'

Test and enable the elasticsearch service
    
    sudo systemctl start elasticsearch
    sudo systemctl enable elasticsearch.service

Install Kibana 5.0.0-alpha5
-------------

Download and unpack

    cd ~
    wget https://download.elastic.co/kibana/kibana/kibana-5.0.0-alpha5-linux-x86_64.tar.gz
    tar xvzf kibana-5.0.0-alpha5-linux-x86_64.tar.gz
    sudo mkdir /nsm/kibana
    sudo mv ~/kibana-5.0.0-alpha5-linux-x86_64/* /nsm/kibana/
    rm ~/kibana* -rf

Add kibana user

    sudo adduser --system --ingroup nsm --home /nsm/kibana --shell /sbin/nologin kibana
    sudo usermod -a -G syslog kibana
    sudo chown kibana.nsm /nsm/kibana -R

Edit /nsm/kibana/etc/kibana.yml to configure these at the bare minimum:

    # Kibana is served by a back end server. This controls which port to use.
    server.port: 5601
    # The host to bind the server to.
    server.host: "0.0.0.0"
    # The Elasticsearch instance to use for all your queries.
    elasticsearch.url: "http://localhost:9200"

Create directories needed by SystemD

    sudo mkdir /var/lib /var/lib/kibana
    sudo chown kibana.nsm /var/lib/kibana

Create kibana job to ensure kibana is always running

    sudo bash -c 'cat > /etc/systemd/system/kibana.service <<EOL
    [Unit]
    Description=Kibana
     
    [Service]
    Type=simple
    User=kibana
    ExecStart=/nsm/kibana/bin/kibana "-c /nsm/kibana/config/kibana.yml"
    Restart=always
    WorkingDirectory=/

    [Install]
    WantedBy=multi-user.target
    EOL'

Test and enable the kibana service
    
    sudo systemctl start kibana
    sudo systemctl enable kibana.service
