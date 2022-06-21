from datetime import datetime, timedelta
from functools import wraps
import token
from flask import Flask, make_response, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import uuid
import jwt

app = Flask(__name__)

#----- Configurations
app.config['SECRET_KEY'] = 'GloryToGod'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///todo.db'

#----_ Integrate sqlalchemy into app
db = SQLAlchemy(app)

#----- Models
class User(db.Model):
        id = db.Column(db.Integer, primary_key= True)
        public_id = db.Column(db.String(50), unique = True)
        name = db.Column(db.String(50))
        password = db.Column(db.String(50))
        admin = db.Column(db.Boolean)

class Todo(db.Model):
        id = db.Column(db.Integer, primary_key= True)
        text = db.Column(db.String(50))
        completed = db.Column(db.Boolean)
        user_id = db.Column(db.String(50))

#----- decorator
def token_required(f):
        @wraps(f)
        def decorated(*args, **kwargs):
                token = None

                if 'x-access-token' in request.headers:
                        token = request.headers['x-access-token']
                
                if not token:
                        return jsonify({"message":"Token is missing!"}), 401

                try:
                        data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
                        current_user = User.query.filter_by(public_id=data['public_id']).first()
                except:
                        return jsonify({'message': 'Token is invalid'}), 401
                
                return f(current_user, *args, **kwargs)

        return decorated

#----- routes
@app.route('/user', methods=['GET'])
@token_required
def get_all_users(current_user):

        if not current_user.admin:
                return jsonify({'message': 'Cannot perform that function'})

        users = User.query.all()

        output = list()

        for user in users:
                user_data = dict()
                user_data['public_id'] = user.public_id
                user_data['name'] =user.name
                user_data['password'] = user.password
                user_data['admin'] = user.admin
                output.append(user_data)
        

        return jsonify({'users': output})

@app.route('/user/<public_id>', methods= ['GET'])
@token_required
def get_one_user(current_user, public_id):
        user = User.query.filter_by(public_id= public_id).first()

        if not user:
                return jsonify({'message': 'No user found'})
        
        user_data = dict()
        user_data['public_id'] = user.public_id
        user_data['name'] =user.name
        user_data['password'] = user.password
        user_data['admin'] = user.admin

        return jsonify({'user': user_data})

@app.route('/user', methods=['POST'])
@token_required
def create_user(current_user):
        data = request.get_json()

        if not data:
                return jsonify({"message": "No new user information supplied"})

        hashed_password = generate_password_hash(data['password'])

        new_user = User(public_id = str(uuid.uuid4()), name= data["name"],password= hashed_password, admin = False)

        db.session.add(new_user)
        db.session.commit()

        return jsonify({"message": f"Account successfully created for {data['name']}"})

@app.route('/user/<public_id>', methods= ['PUT'])
@token_required
def promote_user(current_user, public_id):
        user = User.query.filter_by(public_id= public_id).first()

        if not user:
                return jsonify({'message': 'No user found'})

        user.admin = True

        db.session.commit()

        return jsonify({'message': f"{user.name} promoted successfully"})

@app.route('/user/<public_id>', methods=['DELETE'])
@token_required
def delete_user(current_user, public_id):
        user = User.query.filter_by(public_id= public_id).first()

        if not user:
                return jsonify({'message': 'No user found'})

        db.session.delete(user)
        db.session.commit()

        return jsonify({'message': f"{user.name} Account deleted successfully."})

@app.route("/login")
def login():
        auth = request.authorization

        if not auth or not auth.username or not auth.password:
                return make_response('Could not verify login', 401, {'WWW-Authenticate':'Base realm="Login required!"'})

        user = User.query.filter_by(name= auth.username).first()

        if not user:
                return make_response('Could not verify login', 401, {'WWW-Authenticate':'Base realm="Login required!"'})

        if check_password_hash(user.password, auth.password):
                token = jwt.encode({"public_id": user.public_id, "exp": datetime.utcnow() + timedelta(minutes=30)}, app.config["SECRET_KEY"])

                return jsonify({"token": token})

        return make_response('Could not verify login', 401, {'WWW-Authenticate':'Base realm="Login required!"'})


@app.route('/todo', methods=['GET'])
@token_required
def get_all_todo(current_user):
        todos = Todo.query.filter_by(user_id=current_user.id).all()

        output = list()

        for todo in todos:
                todo_data = dict()
                todo_data['id'] = todo.id
                todo_data['text'] = todo.text
                todo_data['completed'] = todo.completed
                output.append(todo_data)

        return jsonify({"todos": output})


@app.route('/todo/<todo_id>', methods=['GET'])
@token_required
def get_one_todo(current_user, todo_id):
        todo = Todo.query.filter_by(id= todo_id, user_id= current_user.id).first()

        if not todo:
                return jsonify({'message': 'No todo found'})

        todo_data = dict()
        todo_data['id'] = todo.id
        todo_data['text'] = todo.text
        todo_data['completed'] = todo.completed

        return jsonify({'todo': todo_data})

@app.route('/todo', methods=['POST'])
@token_required
def create_todo(current_user):

        data = request.get_json()

        new_todo = Todo(text = data['text'], completed= False, user_id = current_user.id)
        
        db.session.add(new_todo)
        db.session.commit()

        return jsonify({'message': 'Todo created!'})

@app.route('/todo/<todo_id>', methods=['PUT'])
@token_required
def complete_todo(current_user, todo_id):
        todo = Todo.query.filter_by(id= todo_id, user_id= current_user.id).first()

        if not todo:
                return jsonify({'message': 'No todo found'})

        if todo.completed == True:
                todo.completed = False
                db.session.commit()

                return jsonify({'message': 'todo item has been reset!.'})


        elif todo.completed == False:
                todo.completed = True
                db.session.commit()

                return jsonify({'message': 'todo item has been completed!.'})
       

        
@app.route('/todo/<todo_id>', methods=['DELETE'])
@token_required
def delete_todo(current_user, todo_id):
        todo = Todo.query.filter_by(id= todo_id, user_id= current_user.id).first()

        if not todo:
                return jsonify({'message': 'No todo found'})

        db.session.delete(todo)
        db.session.commit()

        return jsonify({'message': 'todo deleted successfully!'})

if __name__ == '__main__':
        app.run(debug= True, port=8000)