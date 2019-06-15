## SmartFactory OAuth2 Server

- Lightweight simple and flexible OAuth2 Server
- With support of the JSON Web Token
- Customizable user suthentication and storage of the token records
- Designed based on IoC 

For more details see [Presentation](http://php-smart-factory.org/oauth2_presentation.pdf) and
[OAuth2 API documentation](http://php-smart-factory.org/oauth2/).

### Requirements

- PHP 7.2.x

### Installation

```
composer require smartfactory/oauth2"
```

**composer.json**
 
```
{
  ...

  "require": {
    "php": ">=7.2",
    "smartfactory/smartfactory": ">=2.1.1",
    "smartfactory/oauth2": ">=1.2.2"
  }
  
  ...
}
```

### To get familiar with the SmartFactory Core and OAuth2 Server do the following:

- Git-clone the demo application [SmartFactoryDemo](https://github.com/oschildt/SmartFactoryDemo) and run 'composer update'.
- Use the script *database/create_database_mysql.sql* (*create_database_mssql.sql*) to create a demo database necessary for some examples.
- View and study the API documentation in the folder docs or here [OAuth2 API documentation](http://php-smart-factory.org/oauth2/).
- Study the core code of the library SmartFactory and SmartFactory OAuth2 Server.
- The example *18.oauth.php* demonstrates usage of the SmartFactory OAuth2 Server.

### To start writing own application using SmartFactory OAuth2 Server

1. Git-clone the demo application [SmartFactoryDemo](https://github.com/oschildt/SmartFactoryDemo) and run 'composer update'.

2. Study the directory structure of the demo application and the code.

3. Implement the interfaces IUserAuthenticator and IUserAuthenticator. 

4. Bind you classes to the interfaces in the file *initialization_inc.php* to be able to use the IoC approach for creating objects offered by the library SmartFactory.

7. Implement the JSON API request handlers.

8. Add translation texts for your application over the *localization/edit.php* or directly into the JSON file *localization/texts.json*. Use the script *localization/check.php* to check your translations for missing translations.

## Directory Structure 

```
docs
src
  OAuth2
    Interfaces
```

## Detailed description

### docs
This directory contains the documentation about classes, interfaces and functions of the SmartFactory OAuth2 Server.

### src
This is the root directory for all classes and interfaces. The class loader is implemented based on PSR4 approach. You have no need to add additional class loader function.

### src/OAuth2
This directory contains the core classes and interfaces of the SmartFactory OAuth2 Server.

### src/OAuth2/Interfaces
This directory contains the core interfaces of the SmartFactory OAuth2 Server.

