#!/bin/bash

if [ ! -z "$ZSH_NAME" ]; then
    autoload bashcompinit
    bashcompinit
fi

_docker_trace () {
    if [ $COMP_CWORD = 1 ]; then
	    COMPREPLY=($(docker-trace -h 2>/dev/null | awk '{print $1}' | grep "^${COMP_WORDS[$COMP_CWORD]}"))
    fi
}

complete -F _docker_trace docker-trace
