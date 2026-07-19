import os
import glob

replacements = {
    '"[OK]       ': 'display.OK() + "',
    '"[DRIFT]    ': 'display.DRIFT() + "',
    '"[NEW]      ': 'display.NEW() + "',
    '"[DELETED]  ': 'display.DELETED() + "',
    '"[FIXED]   ': 'display.FIXED() + "',
    '"[FAILED]  ': 'display.FAILED() + "',
    '"[SKIP]    ': 'display.SKIP() + "',
    '"[INFO] ': 'display.INFO() + "',
    
    # variants with different spacing
    '"[OK]   ': 'display.OK() + "',
    '"[OK] ': 'display.OK() + "',
    '"[DRIFT] ': 'display.DRIFT() + "',
    '"[NEW] ': 'display.NEW() + "',
    '"[DELETED] ': 'display.DELETED() + "',
    '"[FIXED] ': 'display.FIXED() + "',
    '"[FAILED] ': 'display.FAILED() + "',
    '"[SKIP] ': 'display.SKIP() + "',
}

# files to check
files = glob.glob("internal/**/*.go", recursive=True) + glob.glob("cmd/**/*.go", recursive=True)

for filepath in files:
    if "display.go" in filepath:
        continue
    with open(filepath, "r") as f:
        content = f.read()
    
    modified = content
    for old, new in replacements.items():
        modified = modified.replace(old, new)
        
    if modified != content:
        # Check if "github.com/SuryaTK2007/DriftShield/internal/display" is imported
        if "github.com/SuryaTK2007/DriftShield/internal/display" not in modified:
            if '"fmt"' in modified:
                modified = modified.replace('"fmt"', '"fmt"\n\t"github.com/SuryaTK2007/DriftShield/internal/display"')
        
        with open(filepath, "w") as f:
            f.write(modified)
        print(f"Updated {filepath}")
