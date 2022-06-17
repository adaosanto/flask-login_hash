#app.py
from flask import Flask, request, session, redirect, url_for, render_template
from passlib.hash import pbkdf2_sha256
from flaskext.mysql import MySQL
import pymysql 
import re 
 
app = Flask(__name__)
 
# Altere isso para sua chave secreta (pode ser qualquer coisa, é para proteção extra)
app.secret_key = 'adaosantos'
 
mysql = MySQL()
   
# Configurações ySQL 
app.config['MYSQL_DATABASE_USER'] = 'root'
app.config['MYSQL_DATABASE_PASSWORD'] = ''
app.config['MYSQL_DATABASE_DB'] = 'teste'
app.config['MYSQL_DATABASE_HOST'] = 'localhost'
mysql.init_app(app)
 
# http://localhost:5000/login/ - Esta á pagina de login
@app.route('/login/', methods=['GET', 'POST'])
def login():
 # setar a cnx MySQL
    conn = mysql.connect()
    cursor = conn.cursor(pymysql.cursors.DictCursor)
  
    # Mensagem de saída se algo der errado...
    msg = ''
    # Verifica se existem solicitações POST de "nome de usuário" e "senha" (formulário enviado pelo usuário).
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form:
        # Variáveis para facilitar a query.
        username = request.form['username']
        password = request.form['password']


        # Verifica se o usuario realmente existe
        cursor.execute('SELECT * FROM accounts WHERE username = %s', (username))
        # Buscar um registro e retornar o resultado.
        account = cursor.fetchone()

        # Validação de senha.
        try:
            hash_password = account['password']
            verify = pbkdf2_sha256.verify(password, hash_password)
        except:
            verify = False
            
    # Se a conta o username existe e o password estiver correta, cria um session de login.
        if verify == True:

            # Criar dados de sessão, podemos acessar esses dados em outras rotas
            session['loggedin'] = True
            session['id'] = account['id']
            session['username'] = account['username']
            # Retorna para nossa homepage
            #return 'Logged in successfully!'
            return redirect(url_for('home'))
        else:
            # A conta não existe ou nome de usuário/senha incorretos
            msg = 'Senha/usuario incorretos'
    
    return render_template('index.html', msg=msg)
 
# http://localhost:5000/register - página de cadastro
@app.route('/register', methods=['GET', 'POST'])
def register():
 # setar a cnx MySQL
    conn = mysql.connect()
    cursor = conn.cursor(pymysql.cursors.DictCursor)
  
    # Mensagem de saída se algo der errado...
    msg = ''
    # Verifica se existem solicitações POST "username", "password" e "email" (formulário enviado pelo usuário).
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form and 'email' in request.form:
        # Criação de variáveis para mais fácil acesso.
        fullname = request.form['fullname']
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
   
  # verica se já existe algum nome de usuario igual ao digitado pelo o usuario.
        cursor.execute('SELECT * FROM accounts WHERE username = %s', (username))
        account = cursor.fetchone()
        # Se já existe...
        if account:
            msg = 'Essa conta já existe!'
        elif not re.match(r'[^@]+@[^@]+\.[^@]+', email):
            msg = 'Invalid email address!'
        elif not re.match(r'[A-Za-z0-9]+', username):
            msg = 'O nome de usuário deve conter apenas caracteres e números!'
        elif not username or not password or not email:
            msg = 'Por favor, preencha o formulário!'
        
        # A conta não existe e os dados do formulário são válidos, agora insira uma nova conta na table.
        else:

            #Criptografa a senha em SHA256.
            password = pbkdf2_sha256.hash(password)
            cursor.execute('INSERT INTO accounts VALUES (NULL, %s, %s, %s, %s)', (fullname, username, password, email)) 
            conn.commit()
   
            msg = 'Você se registrou com sucesso!'
    elif request.method == 'POST':
        # O formulário está vazio... (sem dados POST).
        msg = 'Por favor, preencha o formulário!'
    # Mostrar formulário de cadastro com mensagem (se houver).
    return render_template('register.html', msg=msg)
  
# http://localhost:5000/home - esta será a página inicial, acessível apenas para usuários logados
@app.route('/')
def home():
    # Verifique se o usuário está logado
    if 'loggedin' in session:
   
        # O usuário está logado mostre a página inicial
        return render_template('home.html', username=session['username'])
    # O usuário não está logado redirecionar para a página de login
    return redirect(url_for('login'))
  
# http://localhost:5000/logout - esta será a página de logout
@app.route('/logout')
def logout():
    # Remova os dados da sessão, isso desconectará o usuário.
   session.pop('loggedin', None)
   session.pop('id', None)
   session.pop('username', None)
   # Redirecionar para a página de login
   return redirect(url_for('login'))
 
# http://localhost:5000/profile - esta será a página de perfil, acessível apenas para usuários logados
@app.route('/profile')
def profile(): 
 # Verifique se a conta existe usando MySQL
    conn = mysql.connect()
    cursor = conn.cursor(pymysql.cursors.DictCursor)
  
    # Verifique se o usuário está logado
    if 'loggedin' in session:
        # Precisamos de todas as informações da conta do usuário para que possamos exibi-las na página de perfil
        cursor.execute('SELECT * FROM accounts WHERE id = %s', [session['id']])
        account = cursor.fetchone()
   
        # Mostrar a página de perfil com informações da conta
        return render_template('profile.html', account=account)
    # O usuário não está logado redirecionar para a página de login
    return redirect(url_for('login'))
  
@app.route("/change_name", methods=["POST"])
def change_name():
    # conexão
    conn = mysql.connect()
    cursor = conn.cursor(pymysql.cursors.DictCursor)

 # Verifica se o usuario esta logado
    if 'loggedin' in session:
         # Verifica se existem solicitações POST "change_name"(formulário enviado pelo usuário).
        if request.method == 'POST' and 'change_name' in request.form:
            # setar a variável com o novo nome
            novo_nome = request.form["change_name"]
            if "'" in novo_nome:
                return redirect(url_for('profile'))
                exit
            # Atualiza o nome no bd.
            cursor.execute("UPDATE accounts SET fullname = %s WHERE id = %s", (novo_nome, session['id']))
            conn.commit()
            cursor.fetchone()

            return redirect(url_for('profile'))
    else:
        return redirect(url_for('login'))
if __name__ == '__main__':
    app.run(debug=True)