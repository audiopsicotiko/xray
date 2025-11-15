#!/bin/bash

author=audiopsicotiko
# github=https://github.com/audiopsicotiko/xray

# bash fonts colors
red='\e[31m'
yellow='\e[33m'
gray='\e[90m'
green='\e[92m'
blue='\e[94m'
magenta='\e[95m'
cyan='\e[96m'
none='\e[0m'
_red() { echo -e ${red}$@${none}; }
_blue() { echo -e ${blue}$@${none}; }
_cyan() { echo -e ${cyan}$@${none}; }
_green() { echo -e ${green}$@${none}; }
_yellow() { echo -e ${yellow}$@${none}; }
_magenta() { echo -e ${magenta}$@${none}; }
_red_bg() { echo -e "\e[41m$@${none}"; }

is_err=$(_red_bg ¡Error!)
is_warn=$(_red_bg ¡Advertencia!)

err() {
    echo -e "\n$is_err $@\n" && exit 1
}

warn() {
    echo -e "\n$is_warn $@\n"
}

# root
[[ $EUID != 0 ]] && err "Actualmente no es usuario ${yellow}ROOT.${none}"

# yum or apt-get, ubuntu/debian/centos
cmd=$(type -P apt-get || type -P yum)
[[ ! $cmd ]] && err "Este script solo soporta ${yellow}(Ubuntu o Debian o CentOS)${none}."

# systemd
[[ ! $(type -P systemctl) ]] && {
    err "Este sistema carece de ${yellow}(systemctl)${none}, intenta ejecutar:${yellow} ${cmd} update -y;${cmd} install systemd -y ${none}para reparar este error."
}

# wget installed or none
is_wget=$(type -P wget)

# x64
case $(uname -m) in
amd64 | x86_64)
    is_jq_arch=amd64
    is_core_arch="64"
    ;;
*aarch64* | *armv8*)
    is_jq_arch=arm64
    is_core_arch="arm64-v8a"
    ;;
*)
    err "Este script solo soporta sistemas de 64 bits..."
    ;;
esac

is_core=xray
is_core_name=Xray
is_core_dir=/etc/$is_core
is_core_bin=$is_core_dir/bin/$is_core
is_core_repo=xtls/$is_core-core
is_conf_dir=$is_core_dir/conf
is_log_dir=/var/log/$is_core
is_sh_bin=/usr/local/bin/$is_core
is_sh_dir=$is_core_dir/sh
is_sh_repo=$author/$is_core
is_pkg="wget unzip"
is_config_json=$is_core_dir/config.json
tmp_var_lists=(
    tmpcore
    tmpsh
    tmpjq
    is_core_ok
    is_sh_ok
    is_jq_ok
    is_pkg_ok
)

# tmp dir
tmpdir=$(mktemp -u)
[[ ! $tmpdir ]] && {
    tmpdir=/tmp/tmp-$RANDOM
}

# set up var
for i in ${tmp_var_lists[*]}; do
    export $i=$tmpdir/$i
done

# load bash script.
load() {
    . $is_sh_dir/src/$1
}

# wget add --no-check-certificate
_wget() {
    [[ $proxy ]] && export https_proxy=$proxy
    wget --no-check-certificate $*
}

# print a mesage
msg() {
    case $1 in
    warn)
        local color=$yellow
        ;;
    err)
        local color=$red
        ;;
    ok)
        local color=$green
        ;;
    esac

    echo -e "${color}$(date +'%T')${none}) ${2}"
}

# show help msg
show_help() {
    echo -e "Uso: $0 [-f xxx | -l | -p xxx | -v xxx | -h]"
    echo -e "  -f, --core-file <ruta>          Ruta personalizada del archivo $is_core_name, ej., -f /root/${is_core}-linux-64.zip"
    echo -e "  -l, --local-install             Obtener script de instalación localmente, usar directorio actual"
    echo -e "  -p, --proxy <dirección>         Usar proxy para descargar, ej., -p http://127.0.0.1:2333"
    echo -e "  -v, --core-version <versión>    Versión personalizada de $is_core_name, ej., -v v1.8.1"
    echo -e "  -h, --help                      Mostrar esta ayuda\n"

    exit 0
}

# install dependent pkg
install_pkg() {
    cmd_not_found=
    for i in $*; do
        [[ ! $(type -P $i) ]] && cmd_not_found="$cmd_not_found,$i"
    done
    if [[ $cmd_not_found ]]; then
        pkg=$(echo $cmd_not_found | sed 's/,/ /g')
        msg warn "Instalando paquetes dependientes >${pkg}"
        $cmd install -y $pkg &>/dev/null
        if [[ $? != 0 ]]; then
            [[ $cmd =~ yum ]] && yum install epel-release -y &>/dev/null
            $cmd update -y &>/dev/null
            $cmd install -y $pkg &>/dev/null
            [[ $? == 0 ]] && >$is_pkg_ok
        else
            >$is_pkg_ok
        fi
    else
        >$is_pkg_ok
    fi
}

# download file
download() {
    case $1 in
    core)
        link=https://github.com/${is_core_repo}/releases/latest/download/${is_core}-linux-${is_core_arch}.zip
        [[ $is_core_ver ]] && link="https://github.com/${is_core_repo}/releases/download/${is_core_ver}/${is_core}-linux-${is_core_arch}.zip"
        name=$is_core_name
        tmpfile=$tmpcore
        is_ok=$is_core_ok
        ;;
    sh)
        link=https://github.com/${is_sh_repo}/releases/latest/download/code.zip
        name="Script $is_core_name"
        tmpfile=$tmpsh
        is_ok=$is_sh_ok
        ;;
    jq)
        link=https://github.com/jqlang/jq/releases/download/jq-1.7.1/jq-linux-$is_jq_arch
        name="jq"
        tmpfile=$tmpjq
        is_ok=$is_jq_ok
        ;;
    esac

    msg warn "Descargando ${name} > ${link}"
    if _wget -t 3 -q -c $link -O $tmpfile; then
        mv -f $tmpfile $is_ok
    fi
}

# get server ip
get_ip() {
    export "$(_wget -4 -qO- https://one.one.one.one/cdn-cgi/trace | grep ip=)" &>/dev/null
    [[ -z $ip ]] && export "$(_wget -6 -qO- https://one.one.one.one/cdn-cgi/trace | grep ip=)" &>/dev/null
}

# check background tasks status
check_status() {
    # dependent pkg install fail
    [[ ! -f $is_pkg_ok ]] && {
        msg err "Falló la instalación de paquetes dependientes"
        msg err "Por favor intenta instalar manualmente los paquetes dependientes: $cmd update -y; $cmd install -y $is_pkg"
        is_fail=1
    }

    # download file status
    if [[ $is_wget ]]; then
        [[ ! -f $is_core_ok ]] && {
            msg err "Falló la descarga de ${is_core_name}"
            is_fail=1
        }
        [[ ! -f $is_sh_ok ]] && {
            msg err "Falló la descarga del script ${is_core_name}"
            is_fail=1
        }
        [[ ! -f $is_jq_ok ]] && {
            msg err "Falló la descarga de jq"
            is_fail=1
        }
    else
        [[ ! $is_fail ]] && {
            is_wget=1
            [[ ! $is_core_file ]] && download core &
            [[ ! $local_install ]] && download sh &
            [[ $jq_not_found ]] && download jq &
            get_ip
            wait
            check_status
        }
    fi

    # found fail status, remove tmp dir and exit.
    [[ $is_fail ]] && {
        exit_and_del_tmpdir
    }
}

# parameters check
pass_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
        -f | --core-file)
            [[ -z $2 ]] && {
                err "($1) falta parámetro requerido, uso correcto ejemplo: [$1 /root/$is_core-linux-64.zip]"
            } || [[ ! -f $2 ]] && {
                err "($2) no es un archivo regular."
            }
            is_core_file=$2
            shift 2
            ;;
        -l | --local-install)
            [[ ! -f ${PWD}/src/core.sh || ! -f ${PWD}/$is_core.sh ]] && {
                err "El directorio actual (${PWD}) no es un directorio de script completo."
            }
            local_install=1
            shift 1
            ;;
        -p | --proxy)
            [[ -z $2 ]] && {
                err "($1) falta parámetro requerido, uso correcto ejemplo: [$1 http://127.0.0.1:2333 o -p socks5://127.0.0.1:2333]"
            }
            proxy=$2
            shift 2
            ;;
        -v | --core-version)
            [[ -z $2 ]] && {
                err "($1) falta parámetro requerido, uso correcto ejemplo: [$1 v1.8.1]"
            }
            is_core_ver=v${2#v}
            shift 2
            ;;
        -h | --help)
            show_help
            ;;
        *)
            echo -e "\n${is_err} ($@) parámetro desconocido...\n"
            show_help
            ;;
        esac
    done
    [[ $is_core_ver && $is_core_file ]] && {
        err "No se puede personalizar simultáneamente la versión de ${is_core_name} y el archivo de ${is_core_name}."
    }
}

# exit and remove tmpdir
exit_and_del_tmpdir() {
    rm -rf $tmpdir
    [[ ! $1 ]] && {
        msg err "Oh no.."
        msg err "Hubo un error durante la instalación..."
        echo -e "Reportar problema) https://github.com/${is_sh_repo}/issues"
        echo
        exit 1
    }
    exit
}

# main
main() {

    # check old version
    [[ -f $is_sh_bin && -d $is_core_dir/bin && -d $is_sh_dir && -d $is_conf_dir ]] && {
        err "Se detectó que el script ya está instalado, si deseas reinstalar usa el comando${green} ${is_core} reinstall ${none}."
    }

    # check parameters
    [[ $# -gt 0 ]] && pass_args $@

    # show welcome msg
    clear
    echo
    echo "........... Script $is_core_name por $author .........."
    echo

    # start installing...
    msg warn "Iniciando instalación..."
    [[ $is_core_ver ]] && msg warn "Versión de ${is_core_name}: ${yellow}$is_core_ver${none}"
    [[ $proxy ]] && msg warn "Usando proxy: ${yellow}$proxy${none}"
    # create tmpdir
    mkdir -p $tmpdir
    # if is_core_file, copy file
    [[ $is_core_file ]] && {
        cp -f $is_core_file $is_core_ok
        msg warn "${yellow}Archivo ${is_core_name} usando > $is_core_file${none}"
    }
    # local dir install sh script
    [[ $local_install ]] && {
        >$is_sh_ok
        msg warn "${yellow}Obteniendo script de instalación localmente > $PWD ${none}"
    }

    timedatectl set-ntp true &>/dev/null
    [[ $? != 0 ]] && {
        msg warn "${yellow}\e[4m¡Recordatorio! No se puede configurar sincronización automática de hora, puede afectar el uso del protocolo VMess.${none}"
    }

    # install dependent pkg
    install_pkg $is_pkg &

    # jq
    if [[ $(type -P jq) ]]; then
        >$is_jq_ok
    else
        jq_not_found=1
    fi
    # if wget installed. download core, sh, jq, get ip
    [[ $is_wget ]] && {
        [[ ! $is_core_file ]] && download core &
        [[ ! $local_install ]] && download sh &
        [[ $jq_not_found ]] && download jq &
        get_ip
    }

    # waiting for background tasks is done
    wait

    # check background tasks status
    check_status

    # test $is_core_file
    if [[ $is_core_file ]]; then
        unzip -qo $is_core_ok -d $tmpdir/testzip &>/dev/null
        [[ $? != 0 ]] && {
            msg err "El archivo ${is_core_name} no pasó la prueba."
            exit_and_del_tmpdir
        }
        for i in ${is_core} geoip.dat geosite.dat; do
            [[ ! -f $tmpdir/testzip/$i ]] && is_file_err=1 && break
        done
        [[ $is_file_err ]] && {
            msg err "El archivo ${is_core_name} no pasó la prueba."
            exit_and_del_tmpdir
        }
    fi

    # get server ip.
    [[ ! $ip ]] && {
        msg err "Falló al obtener la IP del servidor."
        exit_and_del_tmpdir
    }

    # create sh dir...
    mkdir -p $is_sh_dir

    # copy sh file or unzip sh zip file.
    if [[ $local_install ]]; then
        cp -rf $PWD/* $is_sh_dir
    else
        unzip -qo $is_sh_ok -d $is_sh_dir
    fi

    # create core bin dir
    mkdir -p $is_core_dir/bin
    # copy core file or unzip core zip file
    if [[ $is_core_file ]]; then
        cp -rf $tmpdir/testzip/* $is_core_dir/bin
    else
        unzip -qo $is_core_ok -d $is_core_dir/bin
    fi

    # add alias
    echo "alias $is_core=$is_sh_bin" >>/root/.bashrc

    # core command
    ln -sf $is_sh_dir/$is_core.sh $is_sh_bin

    # jq
    [[ $jq_not_found ]] && mv -f $is_jq_ok /usr/bin/jq

    # chmod
    chmod +x $is_core_bin $is_sh_bin /usr/bin/jq

    # create log dir
    mkdir -p $is_log_dir

    # show a tips msg
    msg ok "Generando archivo de configuración..."

    # create systemd service
    load systemd.sh
    is_new_install=1
    install_service $is_core &>/dev/null

    # create condf dir
    mkdir -p $is_conf_dir

    load core.sh
    # create a tcp config
    add reality
    # remove tmp dir and exit.
    exit_and_del_tmpdir ok
}

# start.
main $@
