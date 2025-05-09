from flask import render_template, request, redirect, url_for, session, flash
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from models import db, User, Product, Order

def register_routes(app):
    @app.route('/')
    def index():
        products = Product.query.all()
        return render_template('index.html', products=products)

    @app.route('/register', methods=['GET', 'POST'])
    def register():
        if request.method == 'POST':
            username = request.form['username']
            email = request.form['email']
            password = request.form['password']
            role = request.form['role']
            
            if User.query.filter_by(username=username).first() or User.query.filter_by(email=email).first():
                flash('Username or email already exists!', 'error')
                return redirect(url_for('register'))
            
            hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
            user = User(username=username, email=email, password=hashed_password, role=role)
            db.session.add(user)
            db.session.commit()
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
        return render_template('register.html')

    @app.route('/login', methods=['GET', 'POST'])
    def login():
        if current_user.is_authenticated:
            return redirect(url_for('index'))
        if request.method == 'POST':
            username = request.form['username']
            password = request.form['password']
            user = User.query.filter_by(username=username).first()
            if user and check_password_hash(user.password, password):
                login_user(user)
                # Merge anonymous cart with user's cart
                if 'cart' in session:
                    user_cart = session.get('user_cart_' + str(user.id), [])
                    for new_item in session['cart']:
                        for existing_item in user_cart:
                            if existing_item['id'] == new_item['id']:
                                existing_item['quantity'] += new_item['quantity']
                                break
                        else:
                            user_cart.append(new_item)
                    session['user_cart_' + str(user.id)] = user_cart
                    session.pop('cart', None)
                flash('Logged in successfully!', 'success')
                next_page = request.args.get('next', url_for('index'))
                return redirect(next_page)
            flash('Invalid username or password!', 'error')
        return render_template('login.html')

    @app.route('/logout')
    @login_required
    def logout():
        logout_user()
        flash('Logged out successfully!', 'success')
        return redirect(url_for('index'))

    @app.route('/add_to_cart/<int:product_id>', methods=['POST'])
    def add_to_cart(product_id):
        product = Product.query.get_or_404(product_id)
        quantity = int(request.form.get('quantity', 1))
        if quantity > product.quantity:
            flash('Not enough stock available!', 'error')
            return redirect(url_for('index'))
        
        # Use user-specific cart if logged in, else anonymous cart
        cart_key = 'user_cart_' + str(current_user.id) if current_user.is_authenticated else 'cart'
        if cart_key not in session:
            session[cart_key] = []
        
        for item in session[cart_key]:
            if item['id'] == product_id:
                item['quantity'] += quantity
                session.modified = True
                flash('Product added to cart!', 'success')
                return redirect(url_for('index'))
        
        session[cart_key].append({
            'id': product_id,
            'name': product.name,
            'price': product.price,
            'quantity': quantity,
            'image_url': product.image_url
        })
        session.modified = True
        flash('Product added to cart!', 'success')
        return redirect(url_for('index'))

    @app.route('/remove_from_cart/<int:product_id>', methods=['POST'])
    def remove_from_cart(product_id):
        cart_key = 'user_cart_' + str(current_user.id) if current_user.is_authenticated else 'cart'
        if cart_key not in session:
            session[cart_key] = []
        
        session[cart_key] = [item for item in session[cart_key] if item['id'] != product_id]
        session.modified = True
        flash('Product removed from cart!', 'success')
        return redirect(url_for('cart'))

    @app.route('/cart')
    def cart():
        cart_key = 'user_cart_' + str(current_user.id) if current_user.is_authenticated else 'cart'
        cart_items = session.get(cart_key, [])
        total = sum(item['price'] * item['quantity'] for item in cart_items)
        return render_template('cart.html', cart_items=cart_items, total=total)

    @app.route('/checkout', methods=['GET', 'POST'])
    def checkout():
        if not current_user.is_authenticated:
            flash('Please log in to proceed with checkout.', 'error')
            return redirect(url_for('login', next=url_for('checkout')))
        
        cart_key = 'user_cart_' + str(current_user.id)
        cart_items = session.get(cart_key, [])
        if not cart_items:
            flash('Your cart is empty!', 'error')
            return redirect(url_for('cart'))
        
        total = sum(item['price'] * item['quantity'] for item in cart_items)
        
        if request.method == 'POST':
            # Collect checkout details (for simulation)
            name = request.form['name']
            address = request.form['address']
            payment_method = request.form['payment_method']
            
            # Process purchase
            for item in cart_items:
                product = Product.query.get(item['id'])
                if product.quantity < item['quantity']:
                    flash(f"Not enough stock for {product.name}!", 'error')
                    return redirect(url_for('cart'))
                product.quantity -= item['quantity']
                order = Order(
                    user_id=current_user.id,
                    product_id=product.id,
                    quantity=item['quantity'],
                    total=product.price * item['quantity']
                )
                db.session.add(order)
            
            db.session.commit()
            session[cart_key] = []
            session.modified = True
            flash('Purchase successful! Thank you for your order.', 'success')
            return render_template('checkout.html', success=True, cart_items=cart_items, total=total)
        
        return render_template('checkout.html', cart_items=cart_items, total=total, success=False)

    @app.route('/admin')
    @login_required
    def admin():
        if current_user.role != 'admin':
            flash('Access denied! Admins only.', 'error')
            return redirect(url_for('index'))
        products = Product.query.all()
        return render_template('admin.html', products=products)

    @app.route('/admin/add', methods=['GET', 'POST'])
    @login_required
    def add_product():
        if current_user.role != 'admin':
            flash('Access denied! Admins only.', 'error')
            return redirect(url_for('index'))
        if request.method == 'POST':
            name = request.form['name']
            category = request.form['category']
            price = float(request.form['price'])
            quantity = int(request.form['quantity'])
            image_url = request.form.get('image_url')
            product = Product(name=name, category=category, price=price, quantity=quantity, image_url=image_url)
            db.session.add(product)
            db.session.commit()
            flash('Product added successfully!', 'success')
            return redirect(url_for('admin'))
        return render_template('add_product.html')

    @app.route('/admin/edit/<int:id>', methods=['GET', 'POST'])
    @login_required
    def edit_product(id):
        if current_user.role != 'admin':
            flash('Access denied! Admins only.', 'error')
            return redirect(url_for('index'))
        product = Product.query.get_or_404(id)
        if request.method == 'POST':
            product.name = request.form['name']
            product.category = request.form['category']
            product.price = float(request.form['price'])
            product.quantity = int(request.form['quantity'])
            product.image_url = request.form.get('image_url')
            db.session.commit()
            flash('Product updated successfully!', 'success')
            return redirect(url_for('admin'))
        return render_template('edit_product.html', product=product)

    @app.route('/admin/delete/<int:id>')
    @login_required
    def delete_product(id):
        if current_user.role != 'admin':
            flash('Access denied! Admins only.', 'error')
            return redirect(url_for('index'))
        product = Product.query.get_or_404(id)
        db.session.delete(product)
        db.session.commit()
        flash('Product deleted successfully!', 'success')
        return redirect(url_for('admin'))