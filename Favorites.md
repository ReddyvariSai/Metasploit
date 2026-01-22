# Favorites

**Purpose:** Bookmark frequently used modules

## What are Favorites?

Favorites are user-marked modules for quick access.

 Useful when you repeatedly use the same modules.

### Add to Favorites

```
favorite add exploit/windows/smb/ms17_010_eternalblue
```
### Show Favorites

```
favorite list
```
## Manage Favorites
```
# Add current module to favorites
favorite add

# List favorites
favorite list

# Remove from favorites
favorite delete [name_or_number]

```
## Usage Example


```
use exploit/windows/smb/ms17_010_eternalblue
favorite add  # Saves as "eternalblue"
# Later...
use favorite:eternalblue
```
