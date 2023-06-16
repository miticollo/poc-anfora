#!/usr/bin/env bash
#
# Kill all processes created during experiment.

frida-kill -U TamTam
frida-kill -U iMessageAppsViewService
frida-kill -U Messaggi
frida-kill -U Telegram
frida-kill -U ContactViewViewService
frida-kill -U WebDriverAgentRunner-Runner
frida-kill -U AppStore
frida-kill -U SessionShareExtension
frida-kill -U share
frida-kill -U SignalShareExtension
frida-kill -U Signal
frida-kill -U Viber
frida-kill -U app-share-extension

for pid in $(frida-ps -U | grep -i safari | awk '{ print $1 }'); do
  frida-kill -U "${pid}"
done

frida-ps -U | grep contactsd
