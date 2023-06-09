# 🎬 CINEMA APP 
Cinema App is a robust back-end web application constructed using industry-standard Spring and Hibernate frameworks. This application enables users to execute HTTP requests, such as GET, PUT, POST, and DELETE, and work with JSON objects efficiently.

The app has been developed following the principles of SOLID and Object-Oriented Programming (OOP), resulting in a well-structured and maintainable codebase. It uses the widely-adopted CRUD (Create, Read, Update, Delete) methodology to provide a comprehensive solution for managing data within the application.

Cinema App boasts robust user authentication and authorization features to ensure that only authorized personnel can access the application and data. These measures enhance the application's security, providing peace of mind for users.

## 📁 Project Structure

- The presentation layer, also known as the **Controller**, provides a user interface for interacting with the back-end resources. It handles the HTTP requests from the client side and ensures seamless communication between the front-end and back-end of the application.

- The application layer, or **Service** layer, is the heart of the application and drives the core functionalities of the system. It contains the business logic that processes the requests from the presentation layer and generates appropriate responses.

- The data access layer, or **DAO**, is responsible for interacting with the databases to save and retrieve the application data through Hibernate Query Language (HQL) queries.

Cinema App implements a Data Transfer Object (DTO) design pattern to aggregate and encapsulate objects data for efficient transfer between layers. The models are mapped to DTOs and vice versa through a mapper component in the application layer, ensuring clean separation of concerns and maintainability of the codebase.

![3-tier](https://user-images.githubusercontent.com/96411307/195382480-50c2196d-3738-420b-8818-c6b9b08d923f.png)

## 🛠️ Technologies 
- Java 17
- Spring framework(Security/Core/WebMvc)
- Hibernate 5.6.14.Final
- Apache Maven 3.1.1
- Jackson
- MySQL
- Apache Tomcat 9.0.73

## 💻 Feature set of the application
A customer can get access to the application through endpoints, which let ability monitor and interact with the application.
While a web service utilizes the standard HTTP, and arranges a set of the endpoints that cover the usual Create, Read, Update, and Delete (CRUD) operations.

#### The application supports two type of roles:
- User
- Admin

Each role has restricted access to certain resources that can be accessed via the following endpoints:

#### Access level `ALL`
- register a new user `/register`, request `POST`.
- login to the app `/login`, request `POST`
#### Access level `ADMIN`
- get the user by email `/users/by-email`, request `GET`.
- add a new cinema hall `/cinema-halls`, request `POST`.
- add a new movie `/cinema-halls`, request `POST`.
- add a new movie session `/movie-sessions`, request `POST`.
- change the movie session `/movie-sessions/{id}`, request `PUT`.
- delete the movie session `/movie-sessions/{id}`, request `DELETE`.
#### Access level `ADMIN / USER`
- get a list of cinema halls `/cinema-halls`, request `GET`.
- get a list of movies `/movies`, request `GET`.
- get a list of movie sessions for a specified movie and date  
  `/movie-sessions/available?movieId={?}&date={?}`, request `GET`.
#### Access level `USER`
- add the ticket to the shopping cart `shopping-carts/movie-sessions`, request `PUT`.
- get a list of tickets in the user's cart `/shopping-carts/by-user`, request `GET`.
- confirm the ticket order in the shopping cart `/orders/complete`, request `POST`.
- get a list of this user's orders `/orders-user`, request `GET`.

## 🚀 Installation 

Here are the steps to run this app locally:

1. Install JDK v 17.
2. Clone this repository and open it locally.
3. Change data in `resources/db.properties`
``` code
db.driver=YOUR_DRIVER
db.url=YOUR_URL
db.user=YOUR_USERNAME
db.password=YOUR_PASSWORD
```
4. Install Tomcat v.9.0.50.
5. Run the app.
6. You can use the email ` admin@i.ua ` and password `admin123` for authentication as ADMIN, and
 email `user@i.ua` and password `user123` for authentication as USER.
7. You can use Postman to send requests and get response.
8. Enjoy!

## Contributing 🤝

If you'd like to contribute to this project, feel free to submit a pull request.