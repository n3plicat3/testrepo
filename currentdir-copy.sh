age:
#   ./copy.sh myBackupFolder
#   #
#   # If no argument is passed, it defaults to "copiedFiles"
#
#   TARGET_NAME="${1:-copiedFiles}"
#
#   # Create target directory if it doesn't exist
#   mkdir -p "$TARGET_NAME"
#
#   # Copy all items from the current directory into the target
#   # excluding the target itself (prevents recursive meltdown)
#   shopt -s extglob
#   cp -r !( "$TARGET_NAME" ) "$TARGET_NAME"/
#
#   echo "Replication cycle complete. Assets copied into: $TARGET_NAME"
