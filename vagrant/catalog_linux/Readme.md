# Project Title
---
Item Catalog

## Description
---
This web application list sport category and the related items. Use can register account or login using Google account to create, edit and delete items. Users have the only right to manage the item created by themselves.

### Prerequisites
---
- vagrant
- python 2.7
- Flask
- SQLAlchemy

Full dependency of the project, please see `requirements.txt`


### File structures
---

templates:
  - category.html
  - categoryItem.html
  - header.html
  - item_delete.html
  - item_edit.html
  - item_new.html
  - item.html
  - list_content.html
  - login.html
  - main.html
  - profile_edit.html
  - profile.html
  - registration.html
  - warning.html

application:
  - application.py
  - models.py
  - lotsofitem.py

database:
  - categoryitem.db

CSS style:
  - bootstrap@4.3.1

other:
  - client_secrets.json


### Database Structure
---
Schema |   Name   | Type  |  Owner  
--------+----------+-------+---------
public | User     | table | vagrant
public | Category | table | vagrant
public | CateItem | table | vagrant

1. ### Table `User`
Column         |           Type           |                       Modifiers                       | Storage  | Stats target | Description
--------+--------------------------+-------------------------------------------------------+----------+--------------+-------------
 username      | text                     | not null                                              | plain    |              |
 password_hash | text                     | not null                                              | extended |              |
 name          | text                     |                                                       | extended |              |
 g_id          | text                     |                                                       | extended |              |
 email         | text                     |                                                       | extended |              |
 time          | timestamp with time zone | default now()                                         | plain    |              |
 picture       | text                     | not null default nextval('articles_id_seq'::regclass) | plain    |              |

Fnc:
- hash_password() - generate encrypted has password
- verify_password() - verify password
- generate_auth_token() - generate temperate token, expired in 60 seconds
- verify_auth_token() - verify if token expire


 2. ### Table `Category`
Column  |  Type   |                      Modifiers                       | Storage  | Stats target | Description
--------+---------+------------------------------------------------------+----------+--------------+-------------
name    | text    | not null                                             | extended |              |
user_id | integer | foreignkey('User.id')                                | extended |              |
id      | integer | not null default nextval('authors_id_seq'::regclass) | plain    |              |

Serialization:
```
{
   'name'         : self.name,
   'id'           : self.id,
}  
```

 3. ### Table `CateItem`
 Column     |           Type           |                    Modifiers                     | Storage  | Stats target | Description
--------+--------------------------+--------------------------------------------------+----------+--------------+-------------
name        | text                     | not null                                         | extended |              |
description | text                     |                                                  | extended |              |
category_id | int                      | foreignkey('User.id')                            | extended |              |
user_id     | int                      | foreignkey('User.id')                            | extended |              |
time        | timestamp with time zone | default now()                                    | plain    |              |
id          | integer                  | not null default nextval('log_id_seq'::regclass) | plain    |              |

Serialization:
```
{
  'name': self.name,
  'description': self.description,
  'id': self.id
}  
```


### Getting start
---

1. run `models.py` in vagrant to setup database

```
python models.py
```

2. run `lotsofitem.py` in vagrant to insert data into database

```
python lotsofitem.py
```

3. run `application.py` to serve the web app on `localhost:8000`

```
python application.py
```

### Attributions
Bootstrap sample template from https://bootsnipp.com/
