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
}