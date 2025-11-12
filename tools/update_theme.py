#!/usr/bin/env python3
"""
Update HTML theme to black and red theme with Stranger Things aesthetic
"""
import re
import sys

# Color mapping - converting purple/blue back to black and red
REPLACEMENTS = [
    # Purple colors back to red
    (r'#8a2be2', '#ff0000'),
    (r'#c77dff', '#ff3333'),
    (r'#6a1bb2', '#cc0000'),
    (r'rgba\(138, 43, 226,', 'rgba(255, 0, 0,'),
    (r'rgba\(30, 144, 255,', 'rgba(139, 0, 0,'),
    (r'rgba\(220, 20, 60,', 'rgba(255, 0, 0,'),
    # Backgrounds
    (r'background: #0a0e27;', 'background: #000000;'),
    (r'rgba\(15, 15, 35,', 'rgba(10, 0, 0,'),
    (r'rgba\(10, 10, 25,', 'rgba(0, 0, 0,'),
    (r'rgba\(20, 20, 40,', 'rgba(20, 0, 0,'),
    (r'rgba\(25, 25, 45,', 'rgba(30, 0, 0,'),
    # Text colors
    (r'#7a7a9f', '#666'),
    (r'#9a9aaf', '#888'),
    (r'#6a6a7f', '#666'),
    (r'#ff6b9d', '#ff5555'),
]

def update_file(filepath):
    """Update a single file with new theme"""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
        
        original = content
        
        # Apply replacements
        for pattern, replacement in REPLACEMENTS:
            if callable(replacement):
                content = re.sub(pattern, replacement, content)
            else:
                content = re.sub(pattern, replacement, content)
        
        if content != original:
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(content)
            print(f"✓ Updated {filepath}")
            return True
        else:
            print(f"- No changes needed for {filepath}")
            return False
            
    except Exception as e:
        print(f"✗ Error updating {filepath}: {e}")
        return False

if __name__ == '__main__':
    files = sys.argv[1:] if len(sys.argv) > 1 else [
        'Archon/web/beacon.html',
        'Archon/web/builder.html',
        'Archon/web/users.html',
        'Archon/web/stager.html',
    ]
    
    updated = 0
    for filepath in files:
        if update_file(filepath):
            updated += 1
    
    print(f"\nUpdated {updated}/{len(files)} files")
