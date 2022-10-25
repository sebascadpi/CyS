package Interfaz;

import java.awt.Color;
import java.awt.EventQueue;
import java.awt.Font;
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
import java.security.Key;
import java.security.NoSuchAlgorithmException;
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
import javax.swing.SwingConstants;
import javax.swing.border.EmptyBorder;

public class EncryptDecrypt extends JFrame {
	
	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	public static boolean funcionadec = true;
	public static boolean funcionaen = true;
	public static boolean guardao = false;
	private JPanel contentPane;

	/**
	 * Launch the application.
	 */
	public static void main(String[] args) {
		EventQueue.invokeLater(new Runnable() {
			public void run() {
				try {				
					EncryptDecrypt frame = new EncryptDecrypt();
					frame.setTitle("Sistema de Encriptado/Desencriptado");
					frame.setVisible(true);
					frame.setLocationRelativeTo(null);
					
				} catch (Exception e) {
					e.printStackTrace();
				}
			}
		});
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
        Cipher cipher;
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
	
	public static void saveFile(byte[] bytes, String file, String folder) throws IOException {
		
        FileOutputStream fos = new FileOutputStream(folder +file);
        fos.write(bytes);
        fos.close();

    }
	
	public static void Encriptar(File[] archivos)
		    throws NoSuchAlgorithmException, InstantiationException, IllegalAccessException, IOException{
			
	    //Creamos el archivo donde se guardarÃ¡n las claves
		String padre = archivos[0].getParent();
	    try{
	    	new File(padre+"/Clave").mkdirs();
	    	File claves = new File(padre+"/Clave","claves.txt");
			FileWriter myWriter = new FileWriter(claves);
	        try {
	        	
	            for(int i=0; i < archivos.length; i++) {
	
	                //Generamos clave aleatoria
	                KeyGenerator keyGen = KeyGenerator.getInstance("AES");
	                keyGen.init(256); 
	                SecretKey key = keyGen.generateKey();
	                String id = archivos[i].getName();
	
	                //Guardamos la clave en claves.txt 
	                String encodedKey = Base64.getEncoder().encodeToString(key.getEncoded());
	
	                System.out.println("Original " +encodedKey);
	                System.out.println("Original " + key);
	
	                myWriter.write(encodedKey+" "+ id +"\n");
	                                
	                byte[] content = getFile(archivos[i]);	
	                byte[] encrypted = encryptFile(key, content);
	
	                //Guardamos el archivo encriptado
	                String nombre = archivos[i].getName();
	                new File(padre+"/Encriptadas").mkdirs();
	                saveFile(encrypted,nombre,padre+"/Encriptadas/");	
	            }
	            myWriter.close();
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
		    throws NoSuchAlgorithmException, InstantiationException, IllegalAccessException, IOException{
		              
            	String padre = archivos[0].getParent();
            	File f = new File(padre);
            	String abuelo = f.getParent();
            	System.out.println(abuelo);
            	File saber = new File(abuelo+"/Desencriptadas");
            	String[] parts;
             	String llave = ""; 
             	String id = ""; 
            	 try {
                     //Leemos las rutas de las claves del archivo claves.txt
                     Scanner scanner = new Scanner(new File(abuelo+"\\Clave\\claves.txt"));
                     
                     ArrayList<SecretKey> claves = new ArrayList<SecretKey>();	
                     ArrayList<String> ids = new ArrayList<String>();
                     while (scanner.hasNextLine()) {                
		
                        //Leemos la clave del fichero y la decodificamos
                        String linea = scanner.nextLine();
                        System.out.println("linea " + linea);
                        parts = linea.split(" ");
                        llave=parts[0];
                        id=parts[1];

                        byte[] decodedKey = Base64.getDecoder().decode(llave);
                        SecretKey key = new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES"); 
                        
                        claves.add(key);
                        ids.add(id);
                        System.out.println("Descifro " + key);
                     }
		                        
                        for (File file : archivos) {
		                    
		                    if (file.isFile()) {
		                    	System.out.println(file.getName());
		                        byte[] content = getFile(file);
		                        
		                        //Desencriptamos
		                        for(int i = 0;i < claves.size() && ids.get(i)!=file.getName(); i++) {
		                        	
		                        	if(ids.get(i).compareTo(file.getName())==0) {
		                        		
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
				JOptionPane.showMessageDialog(null, label, "Atención", JOptionPane.DEFAULT_OPTION);
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
				
				int n = files.length;
				String s = files[0].getParent()+"\\Encriptadas";
				
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
				} catch (NoSuchAlgorithmException | InstantiationException | IllegalAccessException | IOException e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
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
		
		btnEncrypt.setBounds(112, 154, 81, 27);
		contentPane.add(btnEncrypt);
		btnDecrypt.setBounds(381, 252, 81, 27);
		contentPane.add(btnDecrypt);

		JLabel lblTitulo = new JLabel("Encripta y Desencripta");
		lblTitulo.setFont(new Font("Tw Cen MT", Font.BOLD, 30));
		lblTitulo.setForeground(Color.WHITE);
		lblTitulo.setBounds(20, 20, 294, 50);
		contentPane.add(lblTitulo);
		
		JLabel lblEligeLosArchivos = new JLabel("Escoge los archivos que quieres encriptar");
		lblEligeLosArchivos.setForeground(Color.WHITE);
		lblEligeLosArchivos.setFont(new Font("Tw Cen MT", Font.BOLD, 16));
		lblEligeLosArchivos.setBounds(21, 105, 312, 39);
		contentPane.add(lblEligeLosArchivos);
		
		JLabel lblEscogeLosArchivos = new JLabel("Escoge los archivos que quieres desencriptar");
		lblEscogeLosArchivos.setForeground(Color.WHITE);
		lblEscogeLosArchivos.setFont(new Font("Tw Cen MT", Font.BOLD, 16));
		lblEscogeLosArchivos.setBounds(270, 204, 312, 39);
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
		URL url = EncryptDecrypt.class.getResource("/res/matrix.gif");
		lblFondo.setIcon(new ImageIcon(url));
		lblFondo.setBounds(2, 20, 588, 310);
		contentPane.add(lblFondo);
		
	}
}
