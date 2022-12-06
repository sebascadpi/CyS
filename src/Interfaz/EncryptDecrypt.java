package Interfaz;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.EventQueue;
import java.awt.Font;
import java.awt.GridLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;
import java.util.List;
import java.util.Scanner;
import java.util.ArrayList;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JMenu;
import javax.swing.JMenuBar;
import javax.swing.JMenuItem;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.JTextField;
import javax.swing.SwingConstants;
import javax.swing.border.EmptyBorder;

import net.lingala.zip4j.ZipFile;
import net.lingala.zip4j.io.inputstream.ZipInputStream;
import net.lingala.zip4j.model.FileHeader;
import net.lingala.zip4j.model.LocalFileHeader;
import net.lingala.zip4j.model.ZipParameters;
import net.lingala.zip4j.model.enums.EncryptionMethod;
import java.io.*;

public class EncryptDecrypt extends JFrame {
	
	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	public static boolean guardao = false;
	private JPanel contentPane;
	public static String us = "admin";
	public static String ps = "";
	/**
	 * Launch the application.
	 */
	public static void main(String[] args) {
		EventQueue.invokeLater(new Runnable() {
			@SuppressWarnings("deprecation")
			public void run() {
				try {
					
					// Creamos el panel de inicio de sesión
					JPanel panel = new JPanel(new BorderLayout(5, 5));
					
					// Creamos las etiquetas de usuario y contraseña y las añadimos al panel
				    JPanel label = new JPanel(new GridLayout(0, 1, 2, 2));
				    label.add(new JLabel("Usuario", SwingConstants.RIGHT));
				    label.add(new JLabel("Contraseña", SwingConstants.RIGHT));
				    panel.add(label, BorderLayout.WEST);
				    
				    // Creamos los inputs de usuario y contraseña y los añadimos al panel
				    JPanel controls = new JPanel(new GridLayout(0, 1, 2, 2));
				    JTextField username = new JTextField();
				    controls.add(username);
				    JPasswordField password = new JPasswordField();
				    controls.add(password);
				    panel.add(controls, BorderLayout.CENTER);
				    
				    // Iniciamos el panel
				    JOptionPane.showMessageDialog(null, panel, "Inicio de Sesión", JOptionPane.OK_CANCEL_OPTION);
				    
				    // Revisamos el usuario y contraseña introducidos
				    if(!username.getText().isBlank() && !password.getText().isBlank()) {
				    	
				    	// Asignamos la contraseña
				    	ps = password.getText();
					    ArrayList<String> users = getUsers();
					    Boolean b = false;
					    String pass = "";					    
					    
					    // Si el usuario introducido existe en la base datos se asigna a la variable us global
					    for(int i = 0; i < users.size() && b == false ; i++) {					    					    	
					    	if(username.getText().equals(users.get(i))) {
					    		us = users.get(i);					    		
					    		pass = getString("pass.txt");
					    		b = true;
					    	}
					    }    
					    
					    // Revisamos si el usuario y la contraseña coinciden
					    if(!b)
					    	JOptionPane.showMessageDialog(null,"El usuario o la contraseña son incorrectos","Atención",JOptionPane.ERROR_MESSAGE);
					    else if (password.getText().isBlank()) 
					    	JOptionPane.showMessageDialog(null,"El usuario o la contraseña son incorrectos","Atención",JOptionPane.ERROR_MESSAGE);					    
					    else if(pass.equals(getSecurePassword(ps, getSalt(2)))) {
					    	
					    	// Iniciamos el frame de la aplicación
					    	EncryptDecrypt frame = new EncryptDecrypt();
							frame.setTitle("Sistema de Encriptado/Desencriptado");
							frame.setVisible(true);
							frame.setLocationRelativeTo(null);				    	
					    }
					    else
					    	JOptionPane.showMessageDialog(null,"El usuario o la contraseña son incorrectos","Atención",JOptionPane.ERROR_MESSAGE);		
				    }
				    
				} catch (Exception e) {
					e.printStackTrace();
				}				
			}
		});
	}
	
	public static void crearAdmin() throws IOException {
		
		// Si la carpeta Usuarios no existe se crea
		if(!new File("Usuarios").exists()) {
			
			// Creamos la carpeta
			new File("Usuarios").mkdir();
			new File("Usuarios/admin").mkdir();
		 	Path file = Paths.get("Usuarios");
		 	Files.setAttribute(file, "dos:hidden", true);
			
		 	// Creamos el zip del admin y los archivos que va a contener
			ZipFile zAdmin = new ZipFile("Usuarios/admin/compressedadmin.zip", ps.toCharArray());		
			
			File archivoUsu = new File("users.txt");
			File archivoClv = new File("passes.txt");
			File archivoAes = new File("aes.txt");
			
			FileWriter Wusus = new FileWriter(archivoUsu);
			FileWriter Wclvs = new FileWriter(archivoClv);
			FileWriter Waes = new FileWriter(archivoAes);
			
			// Inicializamos los archivos
	        Wusus.write("admin\n");	
	        Wusus.close();
	        Wclvs.close();
	        Waes.close();
	        
	        List<File> filesToAdd = Arrays.asList(archivoUsu, archivoClv, archivoAes);	        

			// Añadimos los archivos y después los borramos
	        zAdmin.addFiles(filesToAdd, getParameters());	        
	        zAdmin.close();	        
	        
	        archivoUsu.delete();
	        archivoClv.delete();
	        archivoAes.delete();
		}						
	}
	
	public static void addUyP(String usu, String pass) throws IOException {
		
		// Accedemos al zip del admin para añadir el nuevo usuario y contraseña
		ZipFile zAdmin = new ZipFile("Usuarios/admin/compressedadmin.zip", ps.toCharArray());						
		
		// Pillamos las listas de usuarios y contraseñas
		String u = getString("users.txt");
		String p = getString("passes.txt");
        
		File archivoUsu = new File("Usuarios/admin/users.txt");
		File archivoClv = new File("Usuarios/admin/passes.txt");
		
        FileWriter Wusus = new FileWriter(archivoUsu);
        FileWriter Wclvs = new FileWriter(archivoClv);
        
        // Añadimos los datos del nuevo usuario
        Wusus.write(u+usu+"\n");
        Wclvs.write(p+pass+" "+usu+"\n");
        
        Wusus.close();
        Wclvs.close();
        
        // Se añaden al zip
        zAdmin.addFile(archivoUsu);
        zAdmin.addFile(archivoClv, getParameters());        
        zAdmin.close();
		
        // Borramos los archivos creados para actualizar los que hay en el zip
        archivoUsu.delete();
        archivoClv.delete();
	}
	
	@SuppressWarnings("deprecation")
	public static Boolean deleteUyP() throws Exception {
		Boolean dev = false;
	
		// Creamos el panel que pregunta datos para borrar el usuario
		JPanel panel = new JPanel(new BorderLayout(5, 5));
		
		// Creamos y añadimos etiquetas
	    JPanel label = new JPanel(new GridLayout(0, 1, 2, 2));
	    label.add(new JLabel("Usuario a borrar", SwingConstants.LEFT));
	    label.add(new JLabel("Contraseña del admin", SwingConstants.LEFT));
	    panel.add(label, BorderLayout.WEST);
	    
	    // Creamos y añadimos inputs
	    JPanel controls = new JPanel(new GridLayout(0, 1, 2, 2));
	    JTextField username = new JTextField();
	    controls.add(username);
	    JPasswordField password = new JPasswordField();
	    controls.add(password);
	    panel.add(controls, BorderLayout.CENTER);
	    
	    // Enseñamos el panel
	    JOptionPane.showMessageDialog(null, panel, "Borrar Usuario", JOptionPane.DEFAULT_OPTION);
	    
	    ArrayList<String> users = getUsers();
	    Boolean b = false;
	    
	    // Si el usuario introducido está dentro de la lista de usuarios se vamos a empezar a borrar el usuario
	    for(int i = 0; i < users.size() && b == false ; i++) 	    	
	    	if(username.getText().equals(users.get(i)))   		
	    		b = true;
	    	
	    if(!b) 
	    	// No está en la lista de usuarios
	    	JOptionPane.showMessageDialog(null,"El usuario o la contraseña son incorrectos","Atención",JOptionPane.ERROR_MESSAGE);
	    	    	
	    else {
	    	// Recogemos la contraseña del introducida para verificar si es la del admin
	    	String pass = getString("pass.txt");
	    	
	    	if(password.getText().isBlank()) {
	    		us = "admin";
	    		JOptionPane.showMessageDialog(null,"El usuario o la contraseña son incorrectos","Atención",JOptionPane.ERROR_MESSAGE);
	    	}
	    	else if(username.getText().equals("admin")){
	    		JOptionPane.showMessageDialog(null,"El usuario admin no se puede eliminar","Atención",JOptionPane.ERROR_MESSAGE);
	    	}
	    	else if(pass.equals(getSecurePassword(ps, getSalt(2))))  {   
	    		
	    		// Accedemos al zip del admin
	    		ZipFile zAdmin = new ZipFile("Usuarios/admin/compressedadmin.zip", ps.toCharArray());						
	    		
	    		// Pillamos las listas de usuarios y contraseñas
	    		String u = getString("users.txt");
	    		String p = getString("passes.txt");
	    		
	    		// Creamos los archivos en los que vamos a actualizar los datos de los usuarios
				File archivoUsu = new File("Usuarios/admin/users.txt");
				File archivoClv = new File("Usuarios/admin/passes.txt");
				
				FileWriter Wusus = new FileWriter(archivoUsu);
		        FileWriter Wclvs = new FileWriter(archivoClv);
		        
		        // Listas donde vamos a guardar los datos
				ArrayList<String> lineaU = new ArrayList<String>();
				ArrayList<String> lineaP = new ArrayList<String>();
				
				String[] splU = u.split("\n");
				String[] splP = p.split("\n");
				
				for(String s : splU)
					lineaU.add(s);
					
				for(String s2 : splP)
					lineaP.add(s2);
				
				// Se añaden a las listas los usuarios que no coinciden con los datos del usuario a borrar
				for(int i = 0; i < lineaU.size(); i++)
					if(!lineaU.get(i).contains(username.getText())) 
						Wusus.write(lineaU.get(i)+"\n");
					
				
				for(int i = 0; i < lineaP.size(); i++)
					if(!lineaP.get(i).contains(username.getText())) 
						Wclvs.write(lineaP.get(i)+"\n");

		        Wusus.close();
		        Wclvs.close();
		        
		        // Añadimos las listas sin el usuario a borrar
		        zAdmin.addFile(archivoUsu);
		        zAdmin.addFile(archivoClv, getParameters());        
		        zAdmin.close();
				
		        // Borramos la carpeta del usuario borrado
		        File f = new File("Usuarios/"+username.getText()+"/compressed"+username.getText()+".zip");
		        File f2 = new File("Usuarios/"+username.getText());
		        f.delete();
		        f2.delete();
		        
		        // Borramos los archivos creados para actualizar las listas
		        archivoUsu.delete();
		        archivoClv.delete();
	    		
		        // En caso de que se haya borrado el usuario satisfactoriamente
		    	String mensaje = "El usuario "+username.getText()+" ha sido borrado";
		    	JLabel labele = new JLabel("<html><center>"+mensaje+"<br>");
		    	JOptionPane.showMessageDialog(null, labele, "Usuario Borrado", JOptionPane.DEFAULT_OPTION);

	    		dev = true; 
	    	}
	    	else 	    		
	    		JOptionPane.showMessageDialog(null,"El usuario o la contraseña son incorrectos","Atención",JOptionPane.ERROR_MESSAGE);	    	
	    }
	    
	    return dev;
	}
	
	public static String getString(String s) throws IOException{
		String dev = "";
		
		// Creamos un stream donde almacenaremos los bytes del archivo que vamos a extraer del zip
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		
		// Creamos un buffer con un tamaño fijo en el que vamos a meter los datos del archivo que vamos a extraer
        byte[] readBuffer = new byte[4096];
    	Boolean bool = false;
    	
    	// Creamos un entero donde vamos a revisar el número de bytes del archivo que vamos a extraer
    	int readLen;

		if(us.equals("admin") && (s.equals("rsa_pub.txt") || s.equals("rsa_pvt.txt") || s.equals("pass.txt") || s.equals("sal.txt"))) {
			
			// Creamos un InputStream donde vamos a tener los datos del zip del bin
			// y creamos un ZipInputStream donde vamos a guardar el contenido del zip
			InputStream is = EncryptDecrypt.class.getClassLoader().getResourceAsStream("compressedadmin.zip");
			try(ZipInputStream z = new ZipInputStream(is, ps.toCharArray())) {
				LocalFileHeader localFileHeader;
		        
				// Bucle donde se revisa el nombre de los archivos dentro del zip
		        while ((localFileHeader = z.getNextEntry()) != null && bool == false) {		        	
		        	if(localFileHeader.getFileName().equals(s)) {
		        		
		        		// Creamos un stream donde vamos a sacar los datos del del archivo
		        		// y lo vamos a guardar en stream de bytes creado anteriormente
			            try (OutputStream outputStream = baos) {
			            	
			            	while ((readLen = z.read(readBuffer)) != -1) 
			            		outputStream.write(readBuffer, 0, readLen);
			            	
			            	dev = baos.toString();
			            	System.out.println("getString("+s+"): " + dev);
			            	bool = true;
			            }
		        	}
		        }        
	        }			
		}		
		// Si el archivo que queremos extraer distinto de los listados arriba el archivo se va a extraer de esta manera
		else {
			String original = "";
			
			// Esta condición es relevante para la eliminación de usuarios
			if(!us.equals("admin") && (s.equals("users.txt") || s.equals("passes.txt"))) {
				original = us;
				us = "admin";
			}
			String ZipPass = ps;
			
			// Accedemos al zip de donde queremos sacar el string
			ZipFile zipFile = new ZipFile("Usuarios/"+us+"/compressed"+us+".zip", ZipPass.toCharArray());
			FileHeader fileHeader = zipFile.getFileHeader(s);
			InputStream inputStream = zipFile.getInputStream(fileHeader);
			
			// Guardamos los datos del archivo en un byte array que después vamos a traducir a string
			while ((readLen = inputStream.read(readBuffer)) != -1) {
			  baos.write(readBuffer, 0, readLen);
			}
			System.out.println("getString("+s+"): " + new String(baos.toByteArray()));
			zipFile.close();
			dev = new String(baos.toByteArray());
			
			if(!original.equals("")) 
				us = original;			
		}   	
		
		return dev;
	}
	
	@SuppressWarnings("deprecation")
	public static Boolean newUsuario() throws Exception {
		Boolean dev = false;
		
		// Panel donde preguntaremos los datos del nuevo usuario
		JPanel panel = new JPanel(new BorderLayout(5, 5));

	    JPanel label = new JPanel(new GridLayout(0, 1, 2, 2));
	    label.add(new JLabel("Usuario", SwingConstants.LEFT));
	    label.add(new JLabel("Contraseña", SwingConstants.LEFT));
	    label.add(new JLabel("Repetir Contraseña", SwingConstants.LEFT));
	    panel.add(label, BorderLayout.WEST);
	    
	    // Inputs del nombre de usuario, contraseña y repetir contraseña
	    // no hay limitaciones (igual se pone alguna)
	    JPanel controls = new JPanel(new GridLayout(0, 1, 2, 2));
	    JTextField username = new JTextField();
	    controls.add(username);
	    JPasswordField password = new JPasswordField();
	    controls.add(password);
	    JPasswordField repPass = new JPasswordField();
	    controls.add(repPass);
	    panel.add(controls, BorderLayout.CENTER);
	    
	    JOptionPane.showMessageDialog(null, panel, "Nuevo Usuario", JOptionPane.DEFAULT_OPTION);
	    
	    // Lista de usuarios
	    ArrayList<String> users = getUsers();
	    Boolean b = false;
	   
	    // Revisamos si el usuario introducido existe en la base de datos
	    for(int i = 0; i < users.size() && b == false ; i++)	    					    	
	    	if(username.getText().equals(users.get(i)))
	    		b = true;
	    
	    String usu = username.getText();
	    String pass = password.getText();
	    String reppass = repPass.getText();
	    
	    if(pass.isBlank() || usu.isBlank()) 
	    	JOptionPane.showMessageDialog(null, "Ni el usuario ni la contraseña pueden estar en blanco", "Atención", JOptionPane.ERROR_MESSAGE);	        
	    else if(!b && pass.equals(reppass)) {
	    	
	    	// Creamos la nueva carpeta del usuario, sus claves tanto la pública y la privada 
	    	// y también creamos los archivos donde vamos a guardar estos datos
	    	new File("Usuarios/"+usu).mkdir();
	    	
	    	RSA rsa = new RSA();
	    	rsa.genKeyPair(512);
	    	
	    	// Pillamos las claves y creamos la sal para la contraseña
	    	String pub = rsa.getPublicKeyString();
	    	String pvt = rsa.getPrivateKeyString();
	    	String s = getSalt(1).toString();
	    	
	    	File sal = new File("Usuarios/"+usu+"/sal.txt");
	    	File clave = new File("Usuarios/"+usu+"/pass.txt");
	    	File clavePub = new File("Usuarios/"+usu+"/rsa_pub.txt");
	    	File clavePvt = new File("Usuarios/"+usu+"/rsa_pvt.txt");
	    	File aes = new File("Usuarios/"+usu+"/aes.txt");
	    	
	    	FileWriter salt = new FileWriter(sal);
	    	FileWriter wclv = new FileWriter(clave);
	    	FileWriter wpub = new FileWriter(clavePub);
	    	FileWriter wpvt = new FileWriter(clavePvt);
	    	FileWriter waes = new FileWriter(aes);
	    	
	    	// Escribimos los datos en los nuevos archivos
	    	salt.write(s);
	    	wclv.write(getSecurePassword(pass, s.getBytes()));
	    	wpub.write(pub);
	    	wpvt.write(pvt);
	    	
	    	salt.close();
	    	wclv.close();
	    	wpub.close();
	    	wpvt.close();
	    	waes.close();
	    	
			List<File> filesToAdd = Arrays.asList(
			  clavePvt,
			  clave,
			  aes    		  
		    );
			
			List<File> filesToAdd2 = Arrays.asList(
			  clavePub,
			  sal
		    );
		   
			// Añadimos los archivos creados al nuevo zip
	    	ZipFile zipFile = new ZipFile("Usuarios/"+usu+"/compressed"+usu+".zip", pass.toCharArray());
			zipFile.addFiles(filesToAdd, getParameters());
			zipFile.addFiles(filesToAdd2);
			zipFile.close();
			
			// Borramos los nuevos archivos para no poder acceder a ellos desde fuera del zip
			sal.delete();
			clave.delete();
			clavePub.delete();
			clavePvt.delete();			
			aes.delete();
			
			// Añadimos los datos de los usuarios al zip del admin
			addUyP(usu, getSecurePassword(pass, s.getBytes()));
			us = usu;
			ps = pass;
	    	
	    	dev = true;
	    }
	    else if(b)     	
    		JOptionPane.showMessageDialog(null, "Ya hay un usuario con ese nombre", "Atención", JOptionPane.ERROR_MESSAGE);
	    else if(!pass.equals(reppass))
	    	JOptionPane.showMessageDialog(null, "Las contraseñas tienen que coincidir", "Atención", JOptionPane.ERROR_MESSAGE);
	    
	    return dev;
	}
	
	@SuppressWarnings("deprecation")
	public static Boolean cambiarUsuario() throws Exception {
		Boolean dev = false;
		
		// Panel donde preguntamos los datos
		JPanel panel = new JPanel(new BorderLayout(5, 5));

	    JPanel label = new JPanel(new GridLayout(0, 1, 2, 2));
	    label.add(new JLabel("Usuario", SwingConstants.LEFT));
	    label.add(new JLabel("Contraseña", SwingConstants.LEFT));
	    panel.add(label, BorderLayout.WEST);
	    
	    JPanel controls = new JPanel(new GridLayout(0, 1, 2, 2));
	    JTextField username = new JTextField();
	    controls.add(username);
	    JPasswordField password = new JPasswordField();
	    controls.add(password);
	    panel.add(controls, BorderLayout.CENTER);
	    
	    JOptionPane.showMessageDialog(null, panel, "Cambiar Usuario", JOptionPane.DEFAULT_OPTION);
	    
	    // Guardamos el usuario y contraseña actual para volver a ellas si acaso el cambio de usuario falla
	    String origusu = us;
	    String origps = ps;
	    
	    // Lista de usuarios
	    ArrayList<String> users = getUsers();
	    Boolean b = false;
	    
	    // Si el usuario introducido existe en la lista vamos a pasar empezar el proceso de cambiar de usuario 
	    for(int i = 0; i < users.size() && b == false ; i++)    	
	    	if(username.getText().equals(users.get(i))) {    		
	    		us = users.get(i);
	    		ps = password.getText();
	    		b = true;
	    	}	    
	    
	    if(!b) {
	    	us = origusu;
	    	ps = origps;
	    	JOptionPane.showMessageDialog(null,"El usuario o la contraseña son incorrectos","Atención",JOptionPane.ERROR_MESSAGE);
	    }	    	
	    else {
	    	String pass = "";
	    	
	    	// Comprobamos si las contraseñas coinciden
	    	try {
	    		pass = getString("pass.txt");
	    	}
	    	catch (Exception e){
	    		us = origusu;
		    	ps = origps;
		    	JOptionPane.showMessageDialog(null,"El usuario o la contraseña son incorrectos","Atención",JOptionPane.ERROR_MESSAGE);
	    	}    	
	    	
	    	if(password.getText().isBlank()) {
	    		us = origusu;
	    		ps = origps;
	    		JOptionPane.showMessageDialog(null,"El usuario o la contraseña son incorrectos","Atención",JOptionPane.ERROR_MESSAGE);
	    	}	    	
	    	else if(pass.equals(getSecurePassword(ps, getSalt(2))))     		
	    		dev = true; 	    	
	    	else {
	    		us = origusu;
	    		ps = origps;
	    		JOptionPane.showMessageDialog(null,"El usuario o la contraseña son incorrectos","Atención",JOptionPane.ERROR_MESSAGE);	    	
	    	}
	    }
	    return dev;
	}
	
	public static ArrayList<String> getUsers() throws IOException{
		ArrayList<String> dev = new ArrayList<String>();		
		
		// Comprobamos que exista la carpeta admin
		crearAdmin();
		
		// Recuperamos la lista de usuarios existentes en la base de datos
		if(us.equals("admin")) {
			String s = getString("users.txt");        
	        String[] spl = s.split("\n");
	        
	        // Añadimos al arraylist
	        for(int i = 0; i < spl.length; i++) 
	        	dev.add(spl[i]);
		}
		else {
			// Revisamos los nombres de las carpetas
			File f = new File("Usuarios");
			String[] ss = f.list();
			
			for (String s: ss) 
				dev.add(s);
							
		}
        
		return dev;
	}
	
	public static String getSecurePassword(String password, byte[] salt) {
		
        String generatedPassword = null;
        
        // Se genera la contraseña encriptada con hash
        try {
        	
        	// Se selecciona el tipo del algoritmo "SHA-256"
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            
            //Añadimos la sal pasada por parámetro a la hash
            md.update(salt);
            
            // Pasamos la contraseña a bytes
            byte[] bytes = md.digest(password.getBytes());
            StringBuilder sb = new StringBuilder();
            
            // Creamos un string con los bytes del hash creado
            for (int i = 0; i < bytes.length; i++) {
                sb.append(Integer.toString((bytes[i] & 0xff) + 0x100, 16).substring(1));
            }
            generatedPassword = sb.toString();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return generatedPassword;
    }

	private static byte[] getSalt(int i) throws Exception {
	    
		// Hay 2 tipos de casos, uno para crear una nueva sal y otro para pillarla de un archivo
    	byte[] salt = null;
    	switch(i) {
    		case 1:
    			// Creamos una nueva sal con un algoritmo para randomizar los bytes
	    		SecureRandom random = new SecureRandom();
		        salt = new byte[16];
		        random.nextBytes(salt);    
		    break;
    		case 2:
    			// Pillamos el contenido del archivo sal.txt del usuario actual y lo pasamos a bytes
    			salt = getString("sal.txt").getBytes();
    		break;
    	}
	        return salt;
    }	
	
	public static ZipParameters getParameters() {
		
		// Creamos unos parámetros de seguridad para encriptar archivos dentro del zip con algoritmo AES
		ZipParameters zipParameters = new ZipParameters();
		zipParameters.setEncryptFiles(true);
		zipParameters.setEncryptionMethod(EncryptionMethod.AES);
        
		return zipParameters;
	}
	
	public static byte[] getFile(File f) {
		
		// Pillamos los bytes del archivo que queremos encriptar y los pasamos a un array de bytes
        InputStream is = null;
        try {
            is = new FileInputStream(f);
        } catch (FileNotFoundException e2) {
            e2.printStackTrace();
        }
        byte[] content = null;
        try {
            content = new byte[is.available()];
        } catch (IOException e1) {
            e1.printStackTrace();
        }
        try {
            is.read(content);
        } catch (IOException e) {
            e.printStackTrace();
        }

        return content;
    }
	
	public static byte[] encryptFile(Key key, byte[] content) {
		
		// Ciframos los archivos utilizando una clave en algoritmo AES
        Cipher cipher = null;
        byte[] encrypted = null;
        try {
        	
        	cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, (java.security.Key) key);
            encrypted = cipher.doFinal(content);            
            
        } catch (Exception e) {
            e.printStackTrace();
        }
        return encrypted;

    }
	
	public static String encryptAES(Key key, RSA rsa) {
		
		// Ciframos la clave AES con la clave pública RSA del usuario
		Cipher cipher = null;		
		String encryptedAES = "";
		try {	        
	        cipher=Cipher.getInstance("RSA/ECB/PKCS1Padding");
	        cipher.init(Cipher.ENCRYPT_MODE, rsa.PublicKey);
	        
	        byte[] b=cipher.doFinal(key.getEncoded());
	        encryptedAES = new String(Base64.getEncoder().encode(b));
			
		} catch(Exception e) {
			e.printStackTrace();
		}
		
		return encryptedAES;
	}
	
	public static byte[] decryptFile(Key key, byte[] textCryp) {
		
		// Desencriptamos el archivo seleccionado con la clave AES con la que se encriptó el archivo
        Cipher cipher;
        byte[] decrypted = null;
        try {        	
            cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, key);
            decrypted = cipher.doFinal(textCryp);
            
        } catch (Exception e) {
            e.printStackTrace();
        }
        
        return decrypted;
    }
	
	public static SecretKey decryptAES(PrivateKey pvt, String key) {
		
		// Desencriptamos la clave AES del archivo seleccionado con la clave privada del usuario
		Cipher cipher = null;		
		SecretKey decryptedAES = null;
		try {	        
	        cipher=Cipher.getInstance("RSA");
	        cipher.init(Cipher.DECRYPT_MODE, pvt);
	        
	        byte[] decodedKey = Base64.getDecoder().decode(key);
	        decryptedAES = new SecretKeySpec(cipher.doFinal(decodedKey), "AES");
			
		} catch(Exception e) {
			e.printStackTrace();
		}
		
		return decryptedAES;
	}
	
	public static void saveFile(byte[] bytes, String file, String folder) throws IOException {
		
		// Guardamos los archivos en una carpeta
        FileOutputStream fos = new FileOutputStream(folder + file);
        fos.write(bytes);
        fos.close();

    }
	
	public static boolean Encriptar(File[] archivos) throws InvalidKeySpecException, Exception{
		boolean dev = false;
		
	    //Creamos el archivo donde se guardaran las claves
		RSA rsa = new RSA();
		String padre = archivos[0].getParent();
		File clavesAes = null;
	    try{	    	
	    	// Accedemos al zip del admin para añadir las claves aes
			ZipFile zAdmin = new ZipFile("Usuarios/"+us+"/compressed"+us+".zip", ps.toCharArray());						
			
			// Pillamos las claves aes
			String aes = getString("aes.txt");
	        
			clavesAes = new File("Usuarios/"+us,"aes.txt");
			FileWriter waes = new FileWriter(clavesAes);	    	
	    	waes.write(aes);
	    	
	    	// Pillamos la clave pública del zip
	    	rsa.setPublicKeyString(getString("rsa_pub.txt"));	    	
	    	
	        try {	        	
	            for(int i=0; i < archivos.length; i++) {
	
	                //Generamos clave aleatoria
	                KeyGenerator keyGen = KeyGenerator.getInstance("AES");
	                keyGen.init(256); 
	                SecretKey key = keyGen.generateKey();
	                String id = archivos[i].getName();
	                
	                // Pillamos los bytes del archivo actual
	                byte[] content = getFile(archivos[i]);	
	                byte[] encrypted = encryptFile(key, content);
	
	                //Guardamos el archivo encriptado
	                String nombre = archivos[i].getName();
	                new File(padre+"/Encriptadas"+us).mkdirs();
	                saveFile(encrypted,nombre,padre+"/Encriptadas"+us+"/");	
	                
	                //Guardamos la clave en clavesAes.txt 	                
	                String encodedKey = encryptAES(key, rsa);  
	                System.out.println("Con RSA " +encodedKey);
	                System.out.println("Original " + key);
	
	                waes.write(encodedKey+" "+ id +"\n");	                
	            }
	            
	            waes.close();
	            
	            // Añadimos las claves AES a las bases de datos 
	            // y borramos el archivo de texto para que solo se pueda acceder desde el zip
	            zAdmin.addFile(clavesAes);
	            zAdmin.close();  
	            clavesAes.delete();
	            dev = true;
	            
	        } catch (Exception e) {
	            e.printStackTrace();
	            clavesAes.delete();
	        }
	    } catch (IOException e) {
	    	JOptionPane.showMessageDialog(null,"Ha ocurrido un error","Atención",JOptionPane.ERROR_MESSAGE);
	        e.printStackTrace();
	        clavesAes.delete();
	    }
	    
	    return dev;
	}
	
	public static boolean Desencriptar(File[] archivos) throws Exception{
		boolean dev = false;
		
    	String padre = archivos[0].getParent();
    	File f = new File(padre);
    	String abuelo = f.getParent();
    	File saber = new File(abuelo+"/Desencriptadas"+us);
    	String[] parts;
     	String llave = ""; 
     	String id = ""; 
     	
    	try { 			
 			// Pillamos las claves aes
 			String aes = getString("aes.txt");
 	        
 			File clavesAes = new File("Usuarios/"+us,"aes.txt");
 			FileWriter waes = new FileWriter(clavesAes);
 			waes.write(aes);
 			waes.close();
 			
            //Leemos las rutas de las claves del archivo clavesAes.txt
            Scanner scannerAes = new Scanner(clavesAes);	                 
            RSA rsa = new RSA();
             
            rsa.setPrivateKeyString(getString("rsa_pvt.txt"));
             
            ArrayList<SecretKey> claves = new ArrayList<SecretKey>();	
            ArrayList<String> ids = new ArrayList<String>();
            while (scannerAes.hasNextLine()) {
            	
                //Leemos la clave del fichero y la decodificamos
                String linea = scannerAes.nextLine();
                parts = linea.split(" ");
                llave=parts[0];
                id=parts[1];
                
                System.out.println("El string: " + rsa.PrivateKey.toString());
                
                SecretKey key = decryptAES(rsa.PrivateKey, llave);
                claves.add(key);
                ids.add(id);
            }
            scannerAes.close();
            clavesAes.delete();

            for (File file : archivos) {
                
                if (file.isFile()) {
                	
                    byte[] content = getFile(file);
                    
                    //Desencriptamos
                    for(int i = 0; i < claves.size() && ids.get(i) != file.getName(); i++) {
                    	
                    	if(ids.get(i).equals(file.getName())) {
                    		
                    		byte[] decrypted = decryptFile(claves.get(i), content);                       		
                    		
                    		if(decrypted != null) {
                    			if(!saber.exists())
                        			saber.mkdir();
                    			dev = true;
                        		saveFile(decrypted,file.getName(),abuelo+"/Desencriptadas"+us+"/");
                    		}
                    	}                    		
                    }                    
                }
            }           
    	} catch (FileNotFoundException e) {
        	JOptionPane.showMessageDialog(null,"No se han podido encontrar las claves para desencriptar los archivos","Atención",JOptionPane.ERROR_MESSAGE);
        	e.printStackTrace();
        }
    	
    	return dev;
	}	

	/**
	 * Create the frame. 
	 **/
	public EncryptDecrypt() throws IOException {	
	    
		// Se crea el frame de la aplicación
		setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		setBounds(100, 100, 606, 369);
		contentPane = new JPanel();
		contentPane.setBorder(new EmptyBorder(5, 5, 5, 5));
		setContentPane(contentPane);
		contentPane.setLayout(null);
		
		// Declaramos los botones de elegir archivos para encriptar y desencriptar
		JButton btnEncrypt = new JButton("Elegir archivos");
		btnEncrypt.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				
				// Creamos el selector de archivos
				JFileChooser chooser = new JFileChooser();
				chooser.setDialogTitle("Selecciona los archivos a encriptar");
				chooser.setMultiSelectionEnabled(true);
				chooser.showOpenDialog(null);
				
				// Almacenamos los archivos seleccionados
				File[] files = chooser.getSelectedFiles();
				String mensaje="";
				String mensaje2="";
				String s = "";
				
				int n = files.length;
				if(files.length != 0) {
					s = files[0].getParent()+"\\Encriptadas"+us;
					
					try {
						// Encriptamos
						if(Encriptar(files)) {
							
							if(n==1) {
								mensaje="El archivo que has seleccionado ha sido encriptado y guardado en la carpeta \n";
								mensaje2="Archivo Encriptado";
							}
							else {
								mensaje="<html><center>Los "+n+" archivos que has seleccionado han sido encriptados y guardados en la carpeta \n";
								mensaje2="Archivos Encriptados";
							}
							JLabel label = new JLabel("<html><center>"+mensaje+"<br>"+s);
							label.setHorizontalAlignment(SwingConstants.CENTER);
							JOptionPane.showMessageDialog(null, label, mensaje2, JOptionPane.DEFAULT_OPTION);
						}
						else 
							JOptionPane.showMessageDialog(null,"No se han podido encontrar las claves para encriptar los archivos","Atención",JOptionPane.ERROR_MESSAGE);
						
					} catch (Exception e1) {
						
						e1.printStackTrace();
					} 		
				}
							
			}
		});
		
		// Botón para desencriptar
		JButton btnDecrypt = new JButton("Elegir archivos");
		btnDecrypt.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				
				JFileChooser chooser = new JFileChooser();
				chooser.setDialogTitle("Selecciona los archivos a desencriptar");			
				chooser.setMultiSelectionEnabled(true);
				chooser.showOpenDialog(null);
				File[] files = chooser.getSelectedFiles();
				
				int n = files.length;
				
				if(n != 0) {
					String s = files[0].getParent();
					File f = new File(s);
					String s2 = f.getParent()+"\\Desencriptadas"+us;
					String mensaje="";
					String mensaje2="";
				
					try {
						// Desencriptamos
						if(Desencriptar(files)) {
							
							if(n==1) {
								mensaje="El archivo que has seleccionado ha sido desencriptado y guardado en la carpeta \n";
								mensaje2="Archivo Desencriptado";
							}
							else {
								mensaje="<html><center>Los "+n+" archivos que has seleccionado han sido desencriptados y guardados en la carpeta \n";
								mensaje2="Archivos Desencriptados";
							}
							JLabel label = new JLabel("<html><center>"+mensaje+"<br>"+s2);
							label.setHorizontalAlignment(SwingConstants.CENTER);
							JOptionPane.showMessageDialog(null, label, mensaje2, JOptionPane.DEFAULT_OPTION);
						}
						else
							JOptionPane.showMessageDialog(null,"No se han podido encontrar las claves para desencriptar los archivos","Atención",JOptionPane.ERROR_MESSAGE);
					} catch (Exception e1) {
						e1.printStackTrace();
					}
				}
			}
		});
		
		// Añadimos con el usuario actual
		JLabel lblNewLabel = new JLabel("Usuario actual: " + us);
		lblNewLabel.setFont(new Font("Tw Cen MT", Font.BOLD, 13));
		lblNewLabel.setForeground(Color.WHITE);
		lblNewLabel.setBounds(4, 317, 131, 13);
		contentPane.add(lblNewLabel);
		
		// Añadimos los botones de encriptado y desencriptado
		btnEncrypt.setBounds(255, 139, 81, 27);
		contentPane.add(btnEncrypt);
		btnDecrypt.setBounds(255, 243, 81, 27);
		contentPane.add(btnDecrypt);
		
		// Etiqueta con el título de la aplicación
		JLabel lblTitulo = new JLabel("Encripta y Desencripta");
		lblTitulo.setFont(new Font("Tw Cen MT", Font.BOLD, 30));
		lblTitulo.setForeground(Color.WHITE);
		lblTitulo.setBounds(20, 20, 294, 50);
		contentPane.add(lblTitulo);
		
		// Etiqueta sobre el botón de encriptar
		JLabel lblEligeLosArchivos = new JLabel("Escoge los archivos que quieres encriptar");
		lblEligeLosArchivos.setForeground(Color.WHITE);
		lblEligeLosArchivos.setFont(new Font("Tw Cen MT", Font.BOLD, 16));
		lblEligeLosArchivos.setBounds(157, 99, 278, 39);
		contentPane.add(lblEligeLosArchivos);
		
		// Etiqueta sobre el botón de desencriptar
		JLabel lblEscogeLosArchivos = new JLabel("Escoge los archivos que quieres desencriptar");
		lblEscogeLosArchivos.setForeground(Color.WHITE);
		lblEscogeLosArchivos.setFont(new Font("Tw Cen MT", Font.BOLD, 16));
		lblEscogeLosArchivos.setBounds(145, 203, 302, 39);
		contentPane.add(lblEscogeLosArchivos);
		
		// Barra de menú
		JMenuBar menuBar = new JMenuBar();
		menuBar.setBounds(0, 0, 619, 22);
		contentPane.add(menuBar);
		
		// Objeto en la barra de menú
		JMenu mnNewMenu = new JMenu("Opciones");
		menuBar.add(mnNewMenu);
		
		// Lista de usuarios y declaramos objetos que pondremos en la lista de opciones del menú 
		ArrayList<String> users = getUsers();
		JMenuItem mntmNewMenuItemNUsu = new JMenuItem("Nuevo Usuario");
		JMenuItem mntmNewMenuItemSalir = new JMenuItem("Salir");
		JMenuItem mntmNewMenuItemCambio = new JMenuItem("Cambiar Usuario");
		JMenuItem delete = new JMenuItem("Eliminar Usuario");
		
		// Declaramos el botón de nuevo usuario
		mntmNewMenuItemNUsu.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				try {
					
					// Hacemos el proceso y cambiamos los botones de lado
		    		if(newUsuario()) {		    			
		    			lblNewLabel.setText("Usuario actual: " + us);
		    			
		    			if(mnNewMenu.getComponentZOrder(mntmNewMenuItemCambio) == -1) {
		    				mnNewMenu.remove(delete);
		    				mnNewMenu.remove(mntmNewMenuItemNUsu);
				    		mnNewMenu.add(mntmNewMenuItemCambio);
		    				mnNewMenu.remove(mntmNewMenuItemSalir);
				    		mnNewMenu.add(mntmNewMenuItemSalir);
			    			menuBar.updateUI();
			    			mnNewMenu.updateUI();
		    			}
		    			JOptionPane.showMessageDialog(null, "¡Nuevo usuario creado!", "Nuevo Usuario", JOptionPane.DEFAULT_OPTION);			    		
		    		}
				} catch (Exception e1) {
					e1.printStackTrace();
				}						
			}
		});
		
		// Declaramos el botón de eliminar usuario
		delete.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				try {
					deleteUyP();
					us = "admin";
				} catch (Exception e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				}
			}
		});
		
		// Declaramos botón de cambiar usuario
		mntmNewMenuItemCambio.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {					
				try {
					
					// Cambiamos botones de lado y hacemos el cambio
					if(cambiarUsuario()) {	
						lblNewLabel.setText("Usuario actual: " + us);						
			    		JOptionPane.showMessageDialog(null, "Se ha cambiado de usuario satisfactoriamente", "Cambiar Usuario", JOptionPane.DEFAULT_OPTION);	
			    		System.out.println(mnNewMenu.getComponent());
			    		if(!us.equals("admin") && mnNewMenu.getComponentCount() != 2)
			    			mnNewMenu.remove(mntmNewMenuItemNUsu);
			    		else if (us.equals("admin"))
			    			mnNewMenu.add(mntmNewMenuItemNUsu);
			    		
			    		if(!us.equals("admin") && mnNewMenu.getComponentCount() != 2)
			    			mnNewMenu.remove(delete);
			    		else if (us.equals("admin"))
			    			mnNewMenu.add(delete);
			    		
			    		mnNewMenu.remove(mntmNewMenuItemSalir);
			    		mnNewMenu.add(mntmNewMenuItemSalir);
			    		menuBar.updateUI();
		    			mnNewMenu.updateUI();
					}
				} catch (Exception e1) {
					// TODO Auto-generated catch block
					System.out.println(us+" "+ps);
					e1.printStackTrace();
				}
			}
		});	
		
		// Añadimos los botones a la barra
		if(users.size()>1)
			mnNewMenu.add(mntmNewMenuItemCambio);	
		
		if(us.equals("admin")) {				
			mnNewMenu.add(mntmNewMenuItemNUsu);			
			mnNewMenu.add(delete);
		}	
		
		// Declaramos y añadimos el botón de salir
		mntmNewMenuItemSalir.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				System.exit(0);
			}
		});
		mnNewMenu.add(mntmNewMenuItemSalir);		
		
		// Gif de fondo
		JLabel lblFondo = new JLabel("New label");
		URL url = EncryptDecrypt.class.getResource("/matrix.gif");
		lblFondo.setIcon(new ImageIcon(url));
		lblFondo.setBounds(2, 20, 588, 310);
		contentPane.add(lblFondo);
			
	}	
}