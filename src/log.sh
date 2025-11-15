is_log_level_list=(
    debug
    info
    warning
    error
    none
    del
)
log_set() {
    if [[ $2 ]]; then
        for v in ${is_log_level_list[@]}; do
            [[ $(grep -E -i "^${2,,}$" <<<$v) ]] && is_log_level_use=$v && break
        done
        [[ ! $is_log_level_use ]] && {
            err "No se puede reconocer el parámetro log: $@ \nUse $is_core log [${is_log_level_list[@]}] para configuraciones relacionadas.\nNota: el parámetro del solo elimina temporalmente los archivos log; el parámetro none no generará archivos log."
        }
        case $is_log_level_use in
        del)
            rm -rf $is_log_dir/*.log
            msg "\n $(_green Archivos log eliminados temporalmente, si desea deshabilitar completamente la generación de archivos log use: $is_core log none)\n"
            ;;
        none)
            rm -rf $is_log_dir/*.log
            cat <<<$(jq '.log={"loglevel":"none"}' $is_config_json) >$is_config_json
            ;;
        *)
            cat <<<$(jq '.log={access:"/var/log/'$is_core'/access.log",error:"/var/log/'$is_core'/error.log",loglevel:"'$is_log_level_use'"}' $is_config_json) >$is_config_json
            ;;
        esac

        manage restart &
        [[ $2 != 'del' ]] && msg "\nConfiguración de Log actualizada a: $(_green $is_log_level_use)\n"
    else
        case $1 in
        log)
            if [[ -f $is_log_dir/access.log ]]; then
                msg "\n Recordatorio: Presione $(_green Ctrl + C) para salir\n"
                tail -f $is_log_dir/access.log
            else
                err "No se pueden encontrar archivos log."
            fi
            ;;
        *)
            if [[ -f $is_log_dir/error.log ]]; then
                msg "\n Recordatorio: Presione $(_green Ctrl + C) para salir\n"
                tail -f $is_log_dir/error.log
            else
                err "No se pueden encontrar archivos log."
            fi
            ;;
        esac

    fi
}
