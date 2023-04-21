#!/usr/bin/env bash
#
# Xcode Cleanups
# Based on https://github.com/ctreffs/xcode-defaults#%EF%B8%8F-xcode-cleanups

function derived_data() {
  rm -vrdf ~/Library/Developer/Xcode/DerivedData/*
  rm -vrf "$(defaults read com.apple.dt.Xcode.plist IDECustomDerivedDataLocation)"
}

function cache() {
  CACHE=$(getconf DARWIN_USER_CACHE_DIR)
  rm -vrdf "${CACHE}"com.apple.DeveloperTools
  rm -vrdf "${CACHE}"org.llvm.clang."$(whoami)"/ModuleCache
  rm -vrdf "${CACHE}"org.llvm.clang/ModuleCache
  rm -vrdf ~/Library/Caches/com.apple.dt.*/*
  rm -vrf ~/Library/Caches/org.carthage.CarthageKit
}

function temp_files() {
  TMP=$(getconf DARWIN_USER_TEMP_DIR)
  rm -vrdf "${TMP}"*.swift
  rm -vrdf "${TMP}"ibtool*
  rm -vrdf "${TMP}"*IBTOOLD*
  rm -vrdf "${TMP}"supplementaryOutputs-*
  rm -vrdf "${TMP}"xcrun_db
  rm -vrdf "${TMP}"sources-*
  rm -vrdf "${TMP}"com.apple.dt.*
  rm -vrdf "${TMP}"com.apple.test.*
}

function main() {
  xcrun -k
  derived_data
  cache
  temp_files
  rm -vrf ~/Library/MobileDevice/Provisioning\ Profiles
  xcrun -v simctl delete all
}

main "${@}"
exit 0
