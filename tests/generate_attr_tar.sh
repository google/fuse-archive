#!/bin/bash
# Generate test xattr tar package

# Create temporary working directory
TMPDIR=$(mktemp -d)
trap "rm -rf $TMPDIR" EXIT

# 1. Generate file with many xattrs
echo "Generating file with many xattrs..."
mkdir -p "$TMPDIR/many_xattrs"
filename="$TMPDIR/many_xattrs/file${i}.txt"
touch "$filename"
for i in {1..10}; do
    attr_name="user.attr_$(printf "%04d" $i)"
    setfattr -n "$attr_name" -v "value_$i" "$filename"
done

tar --xattrs --xattrs-include="*" -cf many-xattrs.tar -C "$TMPDIR/many_xattrs" .

# 2. Generate file with corrupt xattrs
echo "Generating file with corrupt xattrs..."
mkdir -p "$TMPDIR/xattr_errors"
touch "$TMPDIR/xattr_errors/file.txt"

# Add normal xattr
setfattr -n "user.normal_attr" -v "valid value" "$TMPDIR/xattr_errors/file.txt"

# Add corrupt xattr (using binary data)
echo -n -e "\xff\xfe\xfd" | setfattr -n "user.corrupt_attr" -v - "$TMPDIR/xattr_errors/file.txt"
tar --xattrs --xattrs-include="*" -cf xattr-errors.tar -C "$TMPDIR/xattr_errors" .

# 3. Generate file with long xattr names
echo "Generating file with long xattr names..."
mkdir -p "$TMPDIR/long_xattr_names"
touch "$TMPDIR/long_xattr_names/file.txt"

# Create xattr name close to 255 bytes
LONG_NAME="user.$(head -c 245 /dev/zero | tr '\0' 'x')"  # user. + 245个'x'
setfattr -n "$LONG_NAME" -v "This is a very long attribute name" "$TMPDIR/long_xattr_names/file.txt"

# Create another long name (with special characters)
LONG_SPECIAL_NAME="user.$(head -c 200 /dev/zero | tr '\0' 'a')_!@#$%^&*()"
setfattr -n "$LONG_SPECIAL_NAME" -v "Special characters in long name" "$TMPDIR/long_xattr_names/file.txt"

tar --xattrs --xattrs-include="*" -cf long-xattr-name.tar -C "$TMPDIR/long_xattr_names" .

echo "Generated test files:"
echo "1. many-xattrs.tar      - File with 1000 xattrs"
echo "2. xattr-errors.tar     - Files with corrupt xattr data"
echo "3. long-xattr-name.tar  - File with very long xattr names"
