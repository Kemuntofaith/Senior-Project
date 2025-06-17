# **BACK2SCHOOL DATABASE.**
### I have about 8 tables in my back2school database including;
#### users
#### school_items
#### products
#### carts
#### cart_items
#### wallets
#### orders
#### notifications

### **Next, I'll explaing their purposes below:**

#### **users table**
##### Purpose: Stores information about all system users (parents, schools, and retailers)
##### Contains: User credentials, role type, and school association for parents
##### Key Fields: id (PK), username (unique), password, role, school_id (FK to users.id)

#### **school_items table**
##### Purpose: Tracks which items are approved by each school and any quantity limits
##### Contains: School-specific item policies (allowed/disallowed items and max quantities)
##### Key Fields: id (PK), school_id (FK to users.id), item_name, allowed, max_quantity

#### **products table**
##### Purpose: Stores products offered by retailers in the system
##### Contains: Product details including pricing and inventory levels
##### Key Fields: id (PK), retailer_id (FK to users.id), item_name, price, stock

#### **carts table**
##### Purpose: Manages shopping carts for users
##### Contains: Cart creation information and owner details
##### Key Fields: id (PK), user_id (FK to users.id), created_at

#### **cart_items table**
##### Purpose: Stores the actual items placed in shopping cart.
##### Contains: Product selections, quantities, and compliance status with school rules
##### Key Fields: cart_id (PK/FK to carts.id), product_id (PK/FK to products.id), quantity, is_compliant

#### **wallets table**
##### Purpose: Tracks user balances (both savings and donations)
##### Contains: Current financial balance for each user
##### Key Fields: user_id (PK/FK to users.id), balance

#### **orders table**
##### Purpose: Records completed purchases
##### Contains: Order details including status and totals
##### Key Fields: id (PK), user_id (FK to users.id), cart_id (FK to carts.id), total, status

#### **notifications table**
##### Purpose: Stores system messages for users
##### Contains: Notification content and read status
##### Key Fields: id (PK), user_id (FK to users.id), message, is_read, created_at

# ****Keys in the backtoschool Database****
### **Primary Keys**
##### users.id - Unique identifier for each user (parent, school, or retailer)
##### school_items.id - Unique identifier for each school-approved item
##### products.id - Unique identifier for each retailer product
##### carts.id - Unique identifier for each shopping cart
##### orders.id - Unique identifier for each order
##### notifications.id - Unique identifier for each notification
##### wallets.user_id - Unique identifier for each wallet (which corresponds to a user)

### **Foreign Keys**
##### users.school_id - Links parents to their school (references users.id)
##### school_items.school_id - Links school items to their school (references users.id)
##### products.retailer_id - Links products to their retailer (references users.id)
##### carts.user_id - Links carts to their user (references users.id)
##### cart_items.cart_id - Links cart items to their cart (references carts.id)
##### cart_items.product_id - Links cart items to the product (references products.id)
##### orders.user_id - Links orders to the user who placed it (references users.id)
##### orders.cart_id - Links orders to the cart used (references carts.id)
##### notifications.user_id - Links notifications to the recipient user (references users.id)
##### wallets.user_id - Links wallets to their owner (references users.id)

### **Unique Keys**
##### users.username - Ensures each username is unique across all users

### **Composite Primary Key**
##### cart_items (cart_id, product_id) - Together these form the primary key for the cart_items table, ensuring each product appears only once per cart

### **Special Key Types**
##### AUTO_INCREMENT - Used on primary keys to automatically generate sequential IDs (users.id, school_items.id, products.id, carts.id, orders.id, notifications.id)
##### ENUM - Used to restrict values to specific options:
######    - users.role - Can only be 'parent', 'school', or 'retailer'
######    - orders.status - Can only be 'pending', 'shipped', or 'delivered'