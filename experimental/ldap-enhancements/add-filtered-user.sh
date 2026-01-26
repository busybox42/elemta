#!/bin/bash

# Add User with Filtering Attributes
# Usage: ./add-filtered-user.sh username "Full Name" email department employeeType "Job Title" [phone]

if [ $# -lt 6 ]; then
    echo "Usage: $0 username \"Full Name\" email department employeeType \"Job Title\" [phone]"
    echo ""
    echo "Departments: executive, engineering, sales, marketing, hr, support, operations"
    echo "Employee Types: management, staff, developer, qa, intern, contractor"
    echo ""
    echo "Example:"
    echo "  $0 jdoe \"Jane Doe\" jane.doe@example.com marketing staff \"Marketing Coordinator\" \"+1-555-0110\""
    exit 1
fi

USERNAME="$1"
FULL_NAME="$2"
EMAIL="$3" 
DEPARTMENT="$4"
EMPLOYEE_TYPE="$5"
JOB_TITLE="$6"
PHONE="${7:-+1-555-0000}"

# Extract first and last names
FIRST_NAME=$(echo "$FULL_NAME" | cut -d' ' -f1)
LAST_NAME=$(echo "$FULL_NAME" | cut -d' ' -f2-)

# Generate next available UID number
NEXT_UID=$(docker exec elemta-ldap ldapsearch -x -H ldap://localhost:389 -D "cn=admin,dc=example,dc=com" -w admin -b "ou=people,dc=example,dc=com" "(objectClass=posixAccount)" uidNumber | grep "uidNumber:" | sort -n -k2 | tail -1 | awk '{print $2+1}')

if [ -z "$NEXT_UID" ]; then
    NEXT_UID=6000
fi

echo "🧑‍💼 Adding new user with filtering attributes:"
echo "  Username: $USERNAME"
echo "  Full Name: $FULL_NAME" 
echo "  Email: $EMAIL"
echo "  Department: $DEPARTMENT"
echo "  Employee Type: $EMPLOYEE_TYPE"
echo "  Job Title: $JOB_TITLE"
echo "  Phone: $PHONE"
echo "  UID Number: $NEXT_UID"
echo ""

# Create LDIF for new user
cat > /tmp/new_user.ldif << EOF
dn: uid=$USERNAME,ou=people,dc=example,dc=com
objectClass: inetOrgPerson
objectClass: posixAccount
objectClass: shadowAccount
uid: $USERNAME
cn: $FULL_NAME
sn: $LAST_NAME
givenName: $FIRST_NAME
displayName: $FULL_NAME
mail: $EMAIL
title: $JOB_TITLE
departmentNumber: $DEPARTMENT
employeeType: $EMPLOYEE_TYPE
telephoneNumber: $PHONE
description: $JOB_TITLE in $DEPARTMENT department
userPassword: {SSHA}$(openssl rand -base64 32)
uidNumber: $NEXT_UID
gidNumber: 5000
homeDirectory: /var/mail/$EMAIL
loginShell: /bin/false
EOF

# Add user to LDAP
echo "📝 Adding user to LDAP directory..."
if docker exec -i elemta-ldap ldapadd -x -H ldap://localhost:389 -D "cn=admin,dc=example,dc=com" -w admin < /tmp/new_user.ldif; then
    echo "✅ User $USERNAME added successfully!"
    
    # Show which address books the user will appear in
    echo ""
    echo "📂 User will appear in these address books:"
    echo "  ✓ All Company Users (unless employeeType=test)"
    
    case $EMPLOYEE_TYPE in
        "management")
            echo "  ✓ Management Team"
            ;;
    esac
    
    case $DEPARTMENT in
        "engineering")
            echo "  ✓ Engineering Team"
            ;;
        "sales"|"marketing")
            echo "  ✓ Sales & Marketing"
            ;;
        "support"|"hr")
            echo "  ✓ Support & HR"
            ;;
    esac
    
    echo ""
    echo "🔍 Test the user in address books:"
    echo "  1. Go to http://localhost:8026"
    echo "  2. Login and go to Address Book"
    echo "  3. Search for '$FIRST_NAME' or '$EMAIL'"
    
    # Test the filters
    echo ""
    echo "🧪 Testing LDAP filters for new user..."
    
    # Test if user appears in All Company Users
    if docker exec elemta-ldap ldapsearch -x -H ldap://localhost:389 -D "cn=admin,dc=example,dc=com" -w admin -b "ou=people,dc=example,dc=com" "(&(objectClass=inetOrgPerson)(mail=*)(!(employeeType=test))(uid=$USERNAME))" dn | grep -q "dn:"; then
        echo "  ✅ Found in 'All Company Users'"
    else
        echo "  ❌ NOT found in 'All Company Users'"
    fi
    
    # Test department-specific filters
    if [ "$DEPARTMENT" = "engineering" ]; then
        if docker exec elemta-ldap ldapsearch -x -H ldap://localhost:389 -D "cn=admin,dc=example,dc=com" -w admin -b "ou=people,dc=example,dc=com" "(&(objectClass=inetOrgPerson)(departmentNumber=engineering)(uid=$USERNAME))" dn | grep -q "dn:"; then
            echo "  ✅ Found in 'Engineering Team'"
        fi
    fi
    
    if [ "$EMPLOYEE_TYPE" = "management" ]; then
        if docker exec elemta-ldap ldapsearch -x -H ldap://localhost:389 -D "cn=admin,dc=example,dc=com" -w admin -b "ou=people,dc=example,dc=com" "(&(objectClass=inetOrgPerson)(employeeType=management)(uid=$USERNAME))" dn | grep -q "dn:"; then
            echo "  ✅ Found in 'Management Team'"
        fi
    fi
    
else
    echo "❌ Failed to add user"
    exit 1
fi

# Cleanup
rm -f /tmp/new_user.ldif

echo ""
echo "✨ User creation completed!"
echo "💡 Tip: You can now set a password using scripts/user-manager.sh" 