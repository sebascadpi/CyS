
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
import java.nio.file.StandardCopyOption;
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
	public static boolean funcionadec = true;
	public static boolean funcionaen = true;
	public static boolean guardao = false;
	private JPanel contentPane;
	public static String us = "admin";
	/**
	 * Launch the application.
	 */
	public static void main(String[] args) {
		EventQueue.invokeLater(new Runnable() {
			@SuppressWarnings("deprecation")
			public void run() {
				try {					
					System.out.println(getSecurePassword("admin", getSalt(2)));
					JPanel panel = new JPanel(new BorderLayout(5, 5));

				    JPanel label = new JPanel(new GridLayout(0, 1, 2, 2));
				    label.add(new JLabel("Usuario", SwingConstants.RIGHT));
				    label.add(new JLabel("Contraseña", SwingConstants.RIGHT));
				    panel.add(label, BorderLayout.WEST);
				    
				    JPanel controls = new JPanel(new GridLayout(0, 1, 2, 2));
				    JTextField username = new JTextField();
				    controls.add(username);
				    JPasswordField password = new JPasswordField();
				    controls.add(password);
				    panel.add(controls, BorderLayout.CENTER);
				    
				    JOptionPane.showMessageDialog(null, panel, "Inicio de Sesión", JOptionPane.OK_CANCEL_OPTION);
				    
				    if(!username.getText().isBlank() && !password.getText().isBlank()) {
				    	
					    ArrayList<String> users = getUsers();
					    Boolean b = false;
					    String ps = "";
					    
					    for(int i = 0; i < users.size() && b == false ; i++) {
					    					    	
					    	if(username.getText().equals(users.get(i))) {
					    		us = users.get(i);
					    		ps = getZip(1);
					    		b = true;
					    	}
					    }    
					    
					    if(!b)
					    	JOptionPane.showMessageDialog(null,"El usuario o la contraseña son incorrectos","Atención",JOptionPane.ERROR_MESSAGE);
					    else if (password.getText().isBlank()) 
					    	JOptionPane.showMessageDialog(null,"El usuario o la contraseña son incorrectos","Atención",JOptionPane.ERROR_MESSAGE);					    
					    else if(ps.equals(getSecurePassword(password.getText(), getSalt(2)))) {
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
		
		if(!new File("Usuarios").exists()) {
			
			new File("Usuarios").mkdir();
			new File("Usuarios/admin").mkdir();
		 	Path file = Paths.get("Usuarios");
		 	Files.setAttribute(file, "dos:hidden", true);
			
			ZipFile zAdmin = new ZipFile("Usuarios/admin/compressedadmin.zip", "password".toCharArray());		
			
			File archivoUsu = getArchivo("users.txt");
			File archivoClv = getArchivo("passes.txt");
			
			FileWriter Wusus = new FileWriter(archivoUsu);
			FileWriter Wclvs = new FileWriter(archivoClv);
			
	        Wusus.write("admin\n");	
	        Wusus.close();
	        Wclvs.close();
	        
	        List<File> filesToAdd = Arrays.asList(archivoUsu, archivoClv);	        
	        
	        ZipParameters zipParameters = new ZipParameters();
			zipParameters.setEncryptFiles(true);
			zipParameters.setEncryptionMethod(EncryptionMethod.AES);
	        
	        zAdmin.addFiles(filesToAdd, zipParameters);	        
	        zAdmin.close();	        
	        
	        archivoUsu.delete();
	        archivoClv.delete();
		}						
	}
	
	public static File getArchivo(String s) throws IOException {	
		
		File archivo = null;		
		
		archivo = new File("Usuarios/admin/"+s);
		
		Boolean bool = false;
		InputStream is = EncryptDecrypt.class.getClassLoader().getResourceAsStream("compressedadmin.zip");
		
        try(ZipInputStream z = new ZipInputStream(is, "password".toCharArray())) {
	        LocalFileHeader localFileHeader;	        
	        while ((localFileHeader = z.getNextEntry()) != null && bool == false) {
	        	if(localFileHeader.getFileName().equals(s)) {	        		
			        Files.copy(z, archivo.toPath(), StandardCopyOption.REPLACE_EXISTING);
			        bool = true;
	        	}
	        }        
        }       
        return archivo;
	}
	
	public static void addUyP(String usu, String pass) throws IOException {
		
		ZipFile zAdmin = new ZipFile("Usuarios/admin/compressedadmin.zip", "password".toCharArray());						
		
		String u = getString("users.txt");
		String p = getString("passes.txt");
        
		File archivoUsu = new File("Usuarios/admin/users.txt");
		File archivoClv = new File("Usuarios/admin/passes.txt");
		
        FileWriter Wusus = new FileWriter(archivoUsu);
        FileWriter Wclvs = new FileWriter(archivoClv);
        
        Wusus.write(u+usu+"\n");
        Wclvs.write(p+pass+" "+usu+"\n");
        
        Wusus.close();
        Wclvs.close();
        
        ZipParameters zipParameters = new ZipParameters();
		zipParameters.setEncryptFiles(true);
		zipParameters.setEncryptionMethod(EncryptionMethod.AES);
        
        zAdmin.addFile(archivoUsu);
        zAdmin.addFile(archivoClv, zipParameters);        
        zAdmin.close();
		
        archivoUsu.delete();
        archivoClv.delete();
	}
	
	@SuppressWarnings("deprecation")
	public static Boolean deleteUyP() throws Exception {
		Boolean dev = false;
	
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
	    
	    JOptionPane.showMessageDialog(null, panel, "Borrar Usuario", JOptionPane.DEFAULT_OPTION);
	    
	    ArrayList<String> users = getUsers();
	    Boolean b = false;
	    
	    for(int i = 0; i < users.size() && b == false ; i++) {
	    	
	    	if(username.getText().equals(users.get(i))) {    		
	    		us = users.get(i);
	    		b = true;
	    	}
	    }
	
	    if(!b) {
	    	us = "admin";
	    	JOptionPane.showMessageDialog(null,"El usuario o la contraseña son incorrectos","Atención",JOptionPane.ERROR_MESSAGE);
	    }	    	
	    else {
	    	String ps = getZip(1);
	    	
	    	if(password.getText().isBlank()) {
	    		us = "admin";
	    		JOptionPane.showMessageDialog(null,"El usuario o la contraseña son incorrectos","Atención",JOptionPane.ERROR_MESSAGE);
	    	}
	    	else if(username.getText().equals("admin")){
	    		JOptionPane.showMessageDialog(null,"El usuario admin no se puede eliminar","Atención",JOptionPane.ERROR_MESSAGE);
	    	}
	    	else if(ps.equals(getSecurePassword(password.getText(), getSalt(2))))  {   		
	    		ZipFile zAdmin = new ZipFile("Usuarios/admin/compressedadmin.zip", "password".toCharArray());						
	    		
	    		String u = getString("users.txt");
	    		String p = getString("passes.txt");
	    		
				File archivoUsu = new File("Usuarios/admin/users.txt");
				File archivoClv = new File("Usuarios/admin/passes.txt");
				
				FileWriter Wusus = new FileWriter(archivoUsu);
		        FileWriter Wclvs = new FileWriter(archivoClv);
		        
				ArrayList<String> lineaU = new ArrayList<String>();
				ArrayList<String> lineaP = new ArrayList<String>();
				
				String[] splU = u.split("\n");
				String[] splP = p.split("\n");
				
				for(String s : splU)
					lineaU.add(s);
					
				for(String s2 : splP)
					lineaP.add(s2);
				
				for(int i = 0; i < lineaP.size(); i++)
					if(!lineaU.get(i).contains(username.getText())) 
						Wusus.write(lineaU.get(i)+"\n");
					
				
				for(int i = 0; i < lineaP.size(); i++)
					if(!lineaP.get(i).contains(username.getText())) 
						Wclvs.write(lineaP.get(i)+"\n");

		        Wusus.close();
		        Wclvs.close();
		        
		        ZipParameters zipParameters = new ZipParameters();
				zipParameters.setEncryptFiles(true);
				zipParameters.setEncryptionMethod(EncryptionMethod.AES);
		        
		        zAdmin.addFile(archivoUsu);
		        zAdmin.addFile(archivoClv, zipParameters);        
		        zAdmin.close();
				
		        File f = new File("Usuarios/"+us+"/compressed"+us+".zip");
		        File f2 = new File("Usuarios/"+us);
		        f.delete();
		        f2.delete();
		        
		        archivoUsu.delete();
		        archivoClv.delete();
	    		
	    		dev = true; 
	    	}
	    	else {
	    		us = "admin";
	    		JOptionPane.showMessageDialog(null,"El usuario o la contraseña son incorrectos","Atención",JOptionPane.ERROR_MESSAGE);	    	
	    	}
	    }
	    
	    if(dev) {
	    	String mensaje = "El usuario "+username.getText()+" ha sido borrado";
	    	JLabel labele = new JLabel("<html><center>"+mensaje+"<br>");
	    	JOptionPane.showMessageDialog(null, labele, "Usuario Borrado", JOptionPane.DEFAULT_OPTION);
	    }
	    return dev;
	}
	
	public static String getString(String s) throws IOException{
		String dev = "";
		
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
        byte[] readBuffer = new byte[4096];
    	Boolean bool = false;
    	int readLen;
		
		if(us.equals("admin") && (s.equals("rsa_pub.txt") || s.equals("rsa_pvt.txt") || s.equals("pass.txt") || s.equals("sal.txt"))) {
			InputStream is = EncryptDecrypt.class.getClassLoader().getResourceAsStream("compressedadmin.zip");
			
			try(ZipInputStream z = new ZipInputStream(is, "password".toCharArray())) {
		        LocalFileHeader localFileHeader;
		        
		        while ((localFileHeader = z.getNextEntry()) != null && bool == false) {
		        	if(localFileHeader.getFileName().equals(s)) {
		        		
			            try (OutputStream outputStream = baos) {
			            	
			            	while ((readLen = z.read(readBuffer)) != -1) 
			            		outputStream.write(readBuffer, 0, readLen);
			            	
			            	dev = baos.toString();
			            	System.out.println("Lo que se devuelve getString(): " + dev);
			            	bool = true;
			            }
		        	}
		        }        
	        }			
		}
		else {
			String original = "";
			if(!us.equals("admin") && (s.equals("users.txt") || s.equals("passes.txt"))) {
				original = us;
				us = "admin";
			}
			
			String ZipPass = "password"+us;
			if(us.equals("admin"))
				ZipPass = "password";
			
			ZipFile zipFile = new ZipFile("Usuarios/"+us+"/compressed"+us+".zip", ZipPass.toCharArray());
			System.out.println(s+" ");
			FileHeader fileHeader = zipFile.getFileHeader(s);
			InputStream inputStream = zipFile.getInputStream(fileHeader);

			while ((readLen = inputStream.read(readBuffer)) != -1) {
			  baos.write(readBuffer, 0, readLen);
			}
			System.out.println("Lo que devuelve el getString(): " + new String(baos.toByteArray()));
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
		JPanel panel = new JPanel(new BorderLayout(5, 5));

	    JPanel label = new JPanel(new GridLayout(0, 1, 2, 2));
	    label.add(new JLabel("Usuario", SwingConstants.LEFT));
	    label.add(new JLabel("Contraseña", SwingConstants.LEFT));
	    label.add(new JLabel("Repetir Contraseña", SwingConstants.LEFT));
	    panel.add(label, BorderLayout.WEST);
	    
	    JPanel controls = new JPanel(new GridLayout(0, 1, 2, 2));
	    JTextField username = new JTextField();
	    controls.add(username);
	    JPasswordField password = new JPasswordField();
	    controls.add(password);
	    JPasswordField repPass = new JPasswordField();
	    controls.add(repPass);
	    panel.add(controls, BorderLayout.CENTER);
	    
	    JOptionPane.showMessageDialog(null, panel, "Nuevo Usuario", JOptionPane.DEFAULT_OPTION);
	    System.out.println("abierto");
	    ArrayList<String> users = getUsers();
	    Boolean b = false;
	    
	   for(int i = 0; i < users.size() && b == false ; i++)	    					    	
	    	if(username.getText().equals(users.get(i)))
	    		b = true;
	    
	    String usu = username.getText();
	    String pass = password.getText();
	    String reppass = repPass.getText();
	    
	    if(pass.isBlank() || usu.isBlank()) 
	    	JOptionPane.showMessageDialog(null, "Ni el usuario ni la contraseña pueden estar en blanco", "Atención", JOptionPane.ERROR_MESSAGE);	        
	    else if(!b && pass.equals(reppass)) {
	    	
	    	new File("Usuarios/"+usu).mkdir();
	    	
	    	RSA rsa = new RSA();
	    	rsa.genKeyPair(512);
	    	
	    	String pub = rsa.getPublicKeyString();
	    	String pvt = rsa.getPrivateKeyString();
	    	String s = getSalt(1).toString();
	    	
	    	File sal = new File("Usuarios/"+usu+"/sal.txt");
	    	File clave = new File("Usuarios/"+usu+"/pass.txt");
	    	File clavePub = new File("Usuarios/"+usu+"/rsa_pub.txt");
	    	File clavePvt = new File("Usuarios/"+usu+"/rsa_pvt.txt");
	    	
	    	FileWriter salt = new FileWriter(sal);
	    	FileWriter wclv = new FileWriter(clave);
	    	FileWriter wpub = new FileWriter(clavePub);
	    	FileWriter wpvt = new FileWriter(clavePvt);
	    	
	    	salt.write(s);
	    	wclv.write(getSecurePassword(pass, s.getBytes()));
	    	wpub.write(pub);
	    	wpvt.write(pvt);
	    	
	    	salt.close();
	    	wclv.close();
	    	wpub.close();
	    	wpvt.close();
	    	
	    	ZipParameters zipParameters = new ZipParameters();
			zipParameters.setEncryptFiles(true);
			zipParameters.setEncryptionMethod(EncryptionMethod.AES);
		    
			List<File> filesToAdd = Arrays.asList(
			  clavePvt,
			  clave    		  
		    );
			
			List<File> filesToAdd2 = Arrays.asList(
			  clavePub,
			  sal   		  
		    );
			
			String zipPass = "password"+usu;
		   
	    	ZipFile zipFile = new ZipFile("Usuarios/"+usu+"/compressed"+usu+".zip", zipPass.toCharArray());
			zipFile.addFiles(filesToAdd, zipParameters);
			zipFile.addFiles(filesToAdd2);
			zipFile.close();
			
			sal.delete();
			clave.delete();
			clavePub.delete();
			clavePvt.delete();			
			
			addUyP(usu, getSecurePassword(pass, s.getBytes()));
			us = usu;
	    	
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
	    
	    String original = us;
	    ArrayList<String> users = getUsers();
	    Boolean b = false;
	    
	    for(int i = 0; i < users.size() && b == false ; i++) {
	    	
	    	if(username.getText().equals(users.get(i))) {    		
	    		us = users.get(i);
	    		b = true;
	    	}
	    }
	    
	    if(!b) {
	    	us = original;
	    	JOptionPane.showMessageDialog(null,"El usuario o la contraseña son incorrectos","Atención",JOptionPane.ERROR_MESSAGE);
	    }	    	
	    else {
	    	String ps = getZip(1);
	    	
	    	if(password.getText().isBlank()) {
	    		us = original;
	    		JOptionPane.showMessageDialog(null,"El usuario o la contraseña son incorrectos","Atención",JOptionPane.ERROR_MESSAGE);
	    	}	    	
	    	else if(ps.equals(getSecurePassword(password.getText(), getSalt(2))))     		
	    		dev = true; 	    	
	    	else {
	    		us = original;
	    		JOptionPane.showMessageDialog(null,"El usuario o la contraseña son incorrectos","Atención",JOptionPane.ERROR_MESSAGE);	    	
	    	}
	    }
	    return dev;
	}
	
	public static ArrayList<String> getUsers() throws IOException{
		ArrayList<String> dev = new ArrayList<String>();
		
		crearAdmin();	 	
		String s = getString("users.txt");        
        String[] spl = s.split("\n");
        
        for(int i = 0; i < spl.length; i++) 
        	dev.add(spl[i]);
        
		return dev;
	}
	
	public static String getZip(int i) throws Exception {

		String dev="";		
		String a ="";
		
        switch(i) {
        	case 1:
        		a = "pass.txt";        		
        	break;
        	case 2:
        		a = "rsa_pub.txt";        		
        	break;
        	case 3:
        		a = "rsa_pvt.txt"; 
        	break;
        	case 4:
        		a = "sal.txt";
        	break;
        }
        
     // Extraemos el contendio del archivo
        dev = getString(a);
        
		return dev;		
	}
	
	public static String getSecurePassword(String password, byte[] salt) {

        String generatedPassword = null;
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(salt);
            byte[] bytes = md.digest(password.getBytes());
            StringBuilder sb = new StringBuilder();
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
	    
    	byte[] salt = null;
    	switch(i) {
    		case 1:
	    		SecureRandom random = new SecureRandom();
		        salt = new byte[16];
		        random.nextBytes(salt);
		        
		    break;
    		case 2:
    			String s = getZip(4);
    			salt = s.getBytes();
    			System.out.println(salt);
    		break;
    	}
	        return salt;
    }	
	
	public static byte[] getFile(File f) {

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
		
        FileOutputStream fos = new FileOutputStream(folder +file);
        fos.write(bytes);
        fos.close();

    }
	
	public static void Encriptar(File[] archivos)
		    throws InvalidKeySpecException, Exception{
			
	    //Creamos el archivo donde se guardaran las claves
		RSA rsa = new RSA();
		String padre = archivos[0].getParent();
		File clavesAes = null;
	    try{
	    	new File(padre+"/Claves"+us).mkdirs();
	    	File f = new File(padre+"/Claves"+us);
	    	Path file = Paths.get(f.getPath());
		 	Files.setAttribute(file, "dos:hidden", true);
	    	clavesAes = new File(padre+"/Claves"+us,"aes.txt");
	    	FileWriter myWriteraes = new FileWriter(clavesAes);
	    	
	    	// Pillamos la clave pública del zip
	    	rsa.setPublicKeyString(getZip(2));	    	
	    	
	        try {
	        	
	            for(int i=0; i < archivos.length; i++) {
	
	                //Generamos clave aleatoria
	                KeyGenerator keyGen = KeyGenerator.getInstance("AES");
	                keyGen.init(256); 
	                SecretKey key = keyGen.generateKey();
	                String id = archivos[i].getName();
	                                
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
	
	                myWriteraes.write(encodedKey+" "+ id +"\n");
	                
	            }
	            myWriteraes.close();
	            
	        } catch (FileNotFoundException e) {
	        	funcionaen = false;
	            e.printStackTrace();
	            clavesAes.delete();
	            new File(padre+"/Claves"+us).delete();
	        }
	    } catch (IOException e) {
	    	funcionaen = false;
	        System.out.println("An error occurred.");
	        e.printStackTrace();
	        clavesAes.delete();
	        new File(padre+"/Claves"+us).delete();
	    }
	}
	
	public static void Desencriptar(File[] archivos)
		    throws Exception{
		              
            	String padre = archivos[0].getParent();
            	File f = new File(padre);
            	String abuelo = f.getParent();
            	System.out.println(abuelo);
            	File saber = new File(abuelo+"/Desencriptadas");
            	String[] parts;
             	String llave = ""; 
             	String id = ""; 
             	
            	 try {
                     //Leemos las rutas de las claves del archivo clavesAes.txt
                     Scanner scanneraes = new Scanner(new File(abuelo+"\\Claves"+us+"\\aes.txt"));
                     
                     RSA rsa = new RSA();
                     
                     rsa.setPrivateKeyString(getZip(3));
                     
                     ArrayList<SecretKey> claves = new ArrayList<SecretKey>();	
                     ArrayList<String> ids = new ArrayList<String>();
                     while (scanneraes.hasNextLine()) {                
		
                        //Leemos la clave del fichero y la decodificamos
                        String linea = scanneraes.nextLine();
                        System.out.println("linea " + linea);
                        parts = linea.split(" ");
                        llave=parts[0];
                        id=parts[1];
                        
                        System.out.println("El string: " + rsa.PrivateKey.toString());
                        
                        SecretKey key = decryptAES(rsa.PrivateKey, llave);
                        claves.add(key);
                        ids.add(id);
                        System.out.println("Descifro " + key);
                     }
		                        
                        for (File file : archivos) {
		                    
		                    if (file.isFile()) {
		                    	
		                        byte[] content = getFile(file);
		                        
		                        //Desencriptamos
		                        for(int i = 0;i < claves.size() && ids.get(i)!=file.getName(); i++) {
		                        	
		                        	if(ids.get(i).equals(file.getName())) {
		                        		System.out.println(file.getName());
		                        		byte[] decrypted = decryptFile(claves.get(i), content);
		                        		
		                        		if(!saber.exists()) 
		                        			new File(abuelo+"/Desencriptadas"+us).mkdirs();		                        		
		                        		
			                        	saveFile(decrypted,file.getName(),abuelo+"/Desencriptadas"+us+"/");
		                        	}
		                        }                 
		                    }
		                }
                    
	        } catch (FileNotFoundException e) {
	        	funcionadec = false;
	        	JOptionPane.showMessageDialog(null,"No se han podido encontrar las claves para desencriptar los archivos","Atención",JOptionPane.ERROR_MESSAGE);
	        	System.out.println(e);
	        }
	}
	

	/**
	 * Create the frame.
	 * @throws IOException 
	 */
	public EncryptDecrypt() throws IOException {	
	    	
		setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		setBounds(100, 100, 606, 369);
		contentPane = new JPanel();
		contentPane.setBorder(new EmptyBorder(5, 5, 5, 5));
		setContentPane(contentPane);
		contentPane.setLayout(null);
		
		JButton btnEncrypt = new JButton("Elegir archivos");
		btnEncrypt.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				
				JFileChooser chooser = new JFileChooser();
				chooser.setDialogTitle("Selecciona los archivos a encriptar");
				chooser.setMultiSelectionEnabled(true);
				chooser.showOpenDialog(null);
				File[] files = chooser.getSelectedFiles();
				String mensaje="";
				String mensaje2="";
				String s = "";
				
				int n = files.length;
				if(files.length != 0) {
					s = files[0].getParent()+"\\Encriptadas"+us;
					
					try {
						Encriptar(files);
						if(funcionaen) {
							
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
					} catch (Exception e1) {
						
						e1.printStackTrace();
					} 		
				}
							
			}
		});
		
		JButton btnDecrypt = new JButton("Elegir archivos");
		btnDecrypt.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				
				JFileChooser chooser = new JFileChooser();
				chooser.setDialogTitle("Selecciona los archivos a desencriptar");			
				chooser.setMultiSelectionEnabled(true);
				chooser.showOpenDialog(null);
				File[] files = chooser.getSelectedFiles();
				
				int n = files.length;
				String s = files[0].getParent();
				File f = new File(s);
				String s2 = f.getParent()+"\\Desencriptadas"+us;
				String mensaje="";
				String mensaje2="";
				
				try {
					Desencriptar(files);
					if(funcionadec) {
						
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
				} catch (Exception e1) {
					e1.printStackTrace();
				}
			}
		});
		
		JLabel lblNewLabel = new JLabel("Usuario actual: " + us);
		lblNewLabel.setText("Usuario actual: " + us);
		lblNewLabel.setFont(new Font("Tw Cen MT", Font.BOLD, 13));
		lblNewLabel.setForeground(Color.WHITE);
		lblNewLabel.setBounds(4, 317, 131, 13);
		contentPane.add(lblNewLabel);
		
		btnEncrypt.setBounds(255, 139, 81, 27);
		contentPane.add(btnEncrypt);
		btnDecrypt.setBounds(255, 243, 81, 27);
		contentPane.add(btnDecrypt);
	
		JLabel lblTitulo = new JLabel("Encripta y Desencripta");
		lblTitulo.setFont(new Font("Tw Cen MT", Font.BOLD, 30));
		lblTitulo.setForeground(Color.WHITE);
		lblTitulo.setBounds(20, 20, 294, 50);
		contentPane.add(lblTitulo);
		
		JLabel lblEligeLosArchivos = new JLabel("Escoge los archivos que quieres encriptar");
		lblEligeLosArchivos.setForeground(Color.WHITE);
		lblEligeLosArchivos.setFont(new Font("Tw Cen MT", Font.BOLD, 16));
		lblEligeLosArchivos.setBounds(157, 99, 278, 39);
		contentPane.add(lblEligeLosArchivos);
		
		JLabel lblEscogeLosArchivos = new JLabel("Escoge los archivos que quieres desencriptar");
		lblEscogeLosArchivos.setForeground(Color.WHITE);
		lblEscogeLosArchivos.setFont(new Font("Tw Cen MT", Font.BOLD, 16));
		lblEscogeLosArchivos.setBounds(145, 203, 302, 39);
		contentPane.add(lblEscogeLosArchivos);
		
		JMenuBar menuBar = new JMenuBar();
		menuBar.setBounds(0, 0, 619, 22);
		contentPane.add(menuBar);
		
		JMenu mnNewMenu = new JMenu("Opciones");
		menuBar.add(mnNewMenu);
		
		ArrayList<String> users = getUsers();
		JMenuItem mntmNewMenuItemNUsu = new JMenuItem("Nuevo Usuario");
		JMenuItem mntmNewMenuItemSalir = new JMenuItem("Salir");
		JMenuItem mntmNewMenuItemCambio = new JMenuItem("Cambiar Usuario");
		JMenuItem delete = new JMenuItem("Eliminar Usuario");
		
		
		mntmNewMenuItemCambio.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {					
				try {
					Boolean b = cambiarUsuario();
					
					if(b) {	
						lblNewLabel.setText("Usuario actual: " + us);						
			    		JOptionPane.showMessageDialog(null, "Se ha cambiado de usuario satisfactoriamente", "Cambiar Usuario", JOptionPane.DEFAULT_OPTION);	
			    		
			    		if(!us.equals("admin") && mnNewMenu.getComponentZOrder(mntmNewMenuItemNUsu) != -1)
			    			mnNewMenu.remove(mntmNewMenuItemNUsu);
			    		else if (us.equals("admin"))
			    			mnNewMenu.add(mntmNewMenuItemNUsu);
			    		
			    		if(!us.equals("admin") && mnNewMenu.getComponentZOrder(delete) != -1)
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
					e1.printStackTrace();
				}
			}
		});	
		
		if(users.size()>1)
			mnNewMenu.add(mntmNewMenuItemCambio);	
			
		if(us.equals("admin")) {

			mntmNewMenuItemNUsu.addActionListener(new ActionListener() {
				public void actionPerformed(ActionEvent e) {
					try {
						Boolean b = newUsuario();
			    		if(b) {		    			
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
			
			mnNewMenu.add(mntmNewMenuItemNUsu);	
		}	
		
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
		mnNewMenu.add(delete);
		
		mntmNewMenuItemSalir.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				System.exit(0);
			}
		});
		mnNewMenu.add(mntmNewMenuItemSalir);		
		
		JLabel lblFondo = new JLabel("New label");
		URL url = EncryptDecrypt.class.getResource("/matrix.gif");
		lblFondo.setIcon(new ImageIcon(url));
		lblFondo.setBounds(2, 20, 588, 310);
		contentPane.add(lblFondo);
			
	}	
=======
package Interfaz;

import java.awt.BorderLayout;

import java.awt.Color;
import java.awt.EventQueue;
import java.awt.Font;
import java.awt.GridLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URL;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;
import java.util.Scanner;
import java.util.ArrayList;

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
import net.lingala.zip4j.io.inputstream.ZipInputStream;
import net.lingala.zip4j.model.LocalFileHeader;

public class EncryptDecrypt extends JFrame {
	
	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	public static boolean funcionadec = true;
	public static boolean funcionaen = true;
	public static boolean guardao = false;
	private JPanel contentPane;
	public static String us = "admin";

	/**
	 * Launch the application.
	 */
	public static void main(String[] args) {
		EventQueue.invokeLater(new Runnable() {
			@SuppressWarnings("deprecation")
			public void run() {
				try {					
					JPanel panel = new JPanel(new BorderLayout(5, 5));

				    JPanel label = new JPanel(new GridLayout(0, 1, 2, 2));
				    label.add(new JLabel("Usuario", SwingConstants.RIGHT));
				    label.add(new JLabel("Contraseña", SwingConstants.RIGHT));
				    panel.add(label, BorderLayout.WEST);
				    
				    JPanel controls = new JPanel(new GridLayout(0, 1, 2, 2));
				    JTextField username = new JTextField();
				    controls.add(username);
				    JPasswordField password = new JPasswordField();
				    controls.add(password);
				    panel.add(controls, BorderLayout.CENTER);
				    JOptionPane.showMessageDialog(null, panel, "Inicio de Sesión", JOptionPane.OK_CANCEL_OPTION);
				    String ps = getZip(1);			    
				    
				    if(us.equals(username.getText()) && ps.equals(getSecurePassword(password.getText(), getSalt()))) {
				    	
				    	EncryptDecrypt frame = new EncryptDecrypt();
						frame.setTitle("Sistema de Encriptado/Desencriptado");
						frame.setVisible(true);
						frame.setLocationRelativeTo(null);				    	
				    }
				    else if (!(username.getText().equals("") && password.getText().equals(""))) {
				    	JOptionPane.showMessageDialog(null,"El usuario o la contraseña son incorrectos","Atención",JOptionPane.ERROR_MESSAGE);
				    }				    
				    
				} catch (Exception e) {
					e.printStackTrace();
				}
			}
		});
	}
	
	@SuppressWarnings("resource")
	public static String getZip(int i) throws Exception {
		String dev="";
		
		String a ="";
        switch(i) {
        	case 1:
        		a = "pass.txt";        		
        	break;
        	case 2:
        		a = "rsa_pub.txt";        		
        	break;
        	case 3:
        		a = "rsa_pvt.txt";        		
        }
        
     // Extraemos el archivo
        InputStream is = EncryptDecrypt.class.getClassLoader().getResourceAsStream("compressedadmin.zip");
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        byte[] readBuffer = new byte[4096];
    	Boolean bool = false;
    	int readLen;
    	
		try(ZipInputStream z = new ZipInputStream(is, "password".toCharArray())) {
	        LocalFileHeader localFileHeader;
	        
	        while ((localFileHeader = z.getNextEntry()) != null && bool == false) {
	        	if(localFileHeader.getFileName().equals(a)) {
	        		
		            try (OutputStream outputStream = baos) {
		            	
		            	while ((readLen = z.read(readBuffer)) != -1) 
		            		outputStream.write(readBuffer, 0, readLen);
		            	
		            	dev = baos.toString();
		            	System.out.println("Lo que se devuelve getString(): " + dev);
		            	bool = true;
		            }
	        	}
	        } 
		}
		
		return dev;		
	}
	
	public static String getSecurePassword(String password, byte[] salt) {

        String generatedPassword = null;
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] bytes = md.digest(password.getBytes());
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < bytes.length; i++) {
                sb.append(Integer.toString((bytes[i] & 0xff) + 0x100, 16).substring(1));
            }
            generatedPassword = sb.toString();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return generatedPassword;
    }

    private static byte[] getSalt() throws NoSuchAlgorithmException {
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[16];
        random.nextBytes(salt);
        return salt;
    }	
	
	public static byte[] getFile(File f) {

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
		
        FileOutputStream fos = new FileOutputStream(folder +file);
        fos.write(bytes);
        fos.close();

    }
	
	public static void Encriptar(File[] archivos)
		    throws InvalidKeySpecException, Exception{
			
	    //Creamos el archivo donde se guardaran las claves
		RSA rsa = new RSA();
		String padre = archivos[0].getParent();
		
	    try{
	    	new File(padre+"/Claves").mkdirs();
	    	File clavesAes = new File(padre+"/Claves","aes.txt");
	    	FileWriter myWriteraes = new FileWriter(clavesAes);
	    	
	    	// Pillamos la clave pública del zip
	    	rsa.setPublicKeyString(getZip(2));
	    	
	        try {
	        	
	            for(int i=0; i < archivos.length; i++) {
	
	                //Generamos clave aleatoria
	                KeyGenerator keyGen = KeyGenerator.getInstance("AES");
	                keyGen.init(256); 
	                SecretKey key = keyGen.generateKey();
	                String id = archivos[i].getName();
	                                
	                byte[] content = getFile(archivos[i]);	
	                byte[] encrypted = encryptFile(key, content);
	
	                //Guardamos el archivo encriptado
	                String nombre = archivos[i].getName();
	                new File(padre+"/Encriptadas").mkdirs();
	                saveFile(encrypted,nombre,padre+"/Encriptadas/");	
	                
	                //Guardamos la clave en clavesAes.txt 	                
	                String encodedKey = encryptAES(key, rsa);  
	                System.out.println("Con RSA " +encodedKey);
	                System.out.println("Original " + key);
	
	                myWriteraes.write(encodedKey+" "+ id +"\n");
	                
	            }
	            myWriteraes.close();
	            
	        } catch (FileNotFoundException e) {
	        	funcionaen = false;
	            e.printStackTrace();
	        }
	    } catch (IOException e) {
	    	funcionaen = false;
	        System.out.println("An error occurred.");
	        e.printStackTrace();
	    }
	}
	
	public static void Desencriptar(File[] archivos)
		    throws Exception{
		              
            	String padre = archivos[0].getParent();
            	File f = new File(padre);
            	String abuelo = f.getParent();
            	System.out.println(abuelo);
            	File saber = new File(abuelo+"/Desencriptadas");
            	String[] parts;
             	String llave = ""; 
             	String id = ""; 
             	
            	 try {
                     //Leemos las rutas de las claves del archivo clavesAes.txt
                     Scanner scanneraes = new Scanner(new File(abuelo+"\\Claves\\aes.txt"));
                     
                     RSA rsa = new RSA();
                     
                     rsa.setPrivateKeyString(getZip(3));
                     
                     ArrayList<SecretKey> claves = new ArrayList<SecretKey>();	
                     ArrayList<String> ids = new ArrayList<String>();
                     while (scanneraes.hasNextLine()) {                
		
                        //Leemos la clave del fichero y la decodificamos
                        String linea = scanneraes.nextLine();
                        System.out.println("linea " + linea);
                        parts = linea.split(" ");
                        llave=parts[0];
                        id=parts[1];
                        
                        System.out.println("El string: " + rsa.PrivateKey.toString());
                        
                        SecretKey key = decryptAES(rsa.PrivateKey, llave);
                        claves.add(key);
                        ids.add(id);
                        System.out.println("Descifro " + key);
                     }
		                        
                    for (File file : archivos) {
	                    
	                    if (file.isFile()) {
	                    	
	                        byte[] content = getFile(file);
	                        
	                        //Desencriptamos
	                        for(int i = 0;i < claves.size() && ids.get(i)!=file.getName(); i++) {
	                        	
	                        	if(ids.get(i).equals(file.getName())) {
	                        		System.out.println(file.getName());
	                        		byte[] decrypted = decryptFile(claves.get(i), content);
	                        		
	                        		if(!saber.exists()) 
	                        			new File(abuelo+"/Desencriptadas").mkdirs();		                        		
	                        		
		                        	saveFile(decrypted,file.getName(),abuelo+"/Desencriptadas/");
	                        	}
	                        }                 
	                    }
	                }
                    
	        } catch (FileNotFoundException e) {
	        	funcionadec = false;
	        	String mensaje="";
	        	JLabel label = new JLabel("<html><center>"+mensaje+"<br>");
				label.setHorizontalAlignment(SwingConstants.CENTER);
	        	JOptionPane.showMessageDialog(null,"No se han podido encontrar las claves para desencriptar los archivos","Atención",JOptionPane.ERROR_MESSAGE);
	        	System.out.println(e);
	        }
	}
	
	/**
	 * Create the frame.
	 */
	public EncryptDecrypt() {	
	    	
		setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		setBounds(100, 100, 606, 369);
		contentPane = new JPanel();
		contentPane.setBorder(new EmptyBorder(5, 5, 5, 5));
		setContentPane(contentPane);
		contentPane.setLayout(null);
		
		JButton btnEncrypt = new JButton("Elegir archivos");
		btnEncrypt.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				
				JFileChooser chooser = new JFileChooser();
				chooser.setDialogTitle("Selecciona los archivos a encriptar");
				chooser.setMultiSelectionEnabled(true);
				chooser.showOpenDialog(null);
				File[] files = chooser.getSelectedFiles();
				String mensaje="";
				String mensaje2="";
				String s = "";
				
				int n = files.length;
				if(files.length != 0) {
					s = files[0].getParent()+"\\Encriptadas";
					
					try {
						Encriptar(files);
						if(funcionaen) {
							
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
					} catch (Exception e1) {
						
						e1.printStackTrace();
					} 		
				}
							
			}
		});
		
		JButton btnDecrypt = new JButton("Elegir archivos");
		btnDecrypt.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				
				JFileChooser chooser = new JFileChooser();
				chooser.setDialogTitle("Selecciona los archivos a desencriptar");			
				chooser.setMultiSelectionEnabled(true);
				chooser.showOpenDialog(null);
				File[] files = chooser.getSelectedFiles();
				
				int n = files.length;
				String s = files[0].getParent();
				File f = new File(s);
				String s2 = f.getParent()+"\\Desencriptadas";
				String mensaje="";
				String mensaje2="";
				
				try {
					Desencriptar(files);
					if(funcionadec) {
						
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
				} catch (Exception e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
				}			
			}
		});
		
		btnEncrypt.setBounds(255, 139, 81, 27);
		contentPane.add(btnEncrypt);
		btnDecrypt.setBounds(255, 243, 81, 27);
		contentPane.add(btnDecrypt);
	
		JLabel lblTitulo = new JLabel("Encripta y Desencripta");
		lblTitulo.setFont(new Font("Tw Cen MT", Font.BOLD, 30));
		lblTitulo.setForeground(Color.WHITE);
		lblTitulo.setBounds(20, 20, 294, 50);
		contentPane.add(lblTitulo);
		
		JLabel lblEligeLosArchivos = new JLabel("Escoge los archivos que quieres encriptar");
		lblEligeLosArchivos.setForeground(Color.WHITE);
		lblEligeLosArchivos.setFont(new Font("Tw Cen MT", Font.BOLD, 16));
		lblEligeLosArchivos.setBounds(157, 99, 278, 39);
		contentPane.add(lblEligeLosArchivos);
		
		JLabel lblEscogeLosArchivos = new JLabel("Escoge los archivos que quieres desencriptar");
		lblEscogeLosArchivos.setForeground(Color.WHITE);
		lblEscogeLosArchivos.setFont(new Font("Tw Cen MT", Font.BOLD, 16));
		lblEscogeLosArchivos.setBounds(145, 203, 302, 39);
		contentPane.add(lblEscogeLosArchivos);
		
		JMenuBar menuBar = new JMenuBar();
		menuBar.setBounds(0, 0, 619, 22);
		contentPane.add(menuBar);
		
		JMenu mnNewMenu = new JMenu("Opciones");
		menuBar.add(mnNewMenu);
		
		JMenuItem mntmNewMenuItem = new JMenuItem("Salir");
		mntmNewMenuItem.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				System.exit(0);
			}
		});
		mnNewMenu.add(mntmNewMenuItem);		
		
		JLabel lblFondo = new JLabel("New label");
		URL url = EncryptDecrypt.class.getResource("/matrix.gif");
		lblFondo.setIcon(new ImageIcon(url));
		lblFondo.setBounds(2, 20, 588, 310);
		contentPane.add(lblFondo);			
	}	
>>>>>>> branch 'practica2' of https://github.com/sebascadpi/CyS.git
}