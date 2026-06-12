"""Dataset simulado realista para entrenamiento educativo."""


class SimulatedPhishingDataset:
    def load(self):
        legitimate = [
            ("Recordatorio de matrícula", "https://universidad.example/matricula",
             "Estimado estudiante, revise el calendario oficial de matrícula en el portal institucional."),
            ("Factura disponible", "https://banco.example/facturas",
             "Su estado de cuenta mensual esta disponible en la banca en linea. Ingrese desde el sitio oficial."),
            ("Reunion de proyecto", "https://teams.example/reunion",
             "El equipo se reunira manana a las 10:00 para revisar avances del proyecto final."),
            ("Confirmacion de cita", "https://clinica.example/citas",
             "Su cita fue confirmada. Puede consultar los detalles desde el portal de pacientes."),
            ("Actualizacion de politicas", "https://empresa.example/politicas",
             "Se publicaron nuevas politicas internas. Revise el documento en la intranet corporativa."),
            ("Seguimiento de paquete", "https://courier.example/rastreo/CR102938",
             "Su paquete está en ruta. Use el código de rastreo desde nuestra página oficial."),
            ("Boletin academico", "https://campus.example/noticias",
             "Esta semana se publicaron actividades estudiantiles, becas y charlas de investigación."),
            ("Recuperacion solicitada", "https://servicio.example/seguridad",
             "Se registro una solicitud de recuperacion. Si no fue usted, contacte soporte desde el portal."),
            ("Invitacion a encuesta", "https://calidad.example/encuestas",
             "Queremos conocer su opinión sobre los servicios recibidos durante este semestre."),
            ("Aviso de mantenimiento", "https://hosting.example/status",
             "El servicio tendrá una ventana de mantenimiento programada el sábado de 1 a 3 a.m."),
            ("Entrega de tarea", "https://aula.example/cursos/ia",
             "La tarea del curso debe entregarse antes del viernes por medio del aula virtual."),
            ("Comprobante de pago", "https://pagos.example/comprobantes",
             "Gracias por su pago. El comprobante se encuentra disponible en su perfil de usuario."),
        ]
        phishing = [
            ("Cuenta bloqueada urgente", "http://seguridad-banco.example.verify-login.ru/acceso",
             "Urgente: su cuenta será suspendida. Verifique usuario, contraseña y token en menos de 10 minutos."),
            ("Premio exclusivo", "http://198.51.100.20/premio",
             "Felicidades, gano un premio. Confirme sus datos personales y numero de tarjeta para reclamarlo."),
            ("Actualizacion obligatoria", "http://login-universidad.example-security.com/validar",
             "Debe actualizar su clave inmediatamente o perderá acceso al correo institucional."),
            ("Reembolso pendiente", "http://pagos.example.refund-check.info",
             "Tiene un reembolso pendiente. Ingrese su cédula, cuenta bancaria y contraseña."),
            ("Alerta de seguridad", "http://tiny.example/seguro",
             "Detectamos actividad sospechosa. Haga clic aquí y confirme su identidad ahora."),
            ("Soporte técnico", "http://soporte-remoto.example/install.exe",
             "Instale este archivo adjunto para reparar su equipo y evitar el bloqueo del sistema."),
            ("Validacion de correo", "http://correo.example-login.net/session",
             "Su buzón excedió el límite. Valide usuario y clave para conservar sus mensajes."),
            ("Transferencia retenida", "http://banco.example.secure-auth.top",
             "Una transferencia fue retenida. Acceda de inmediato para desbloquear fondos."),
            ("Oferta limitada", "http://ofertas-gratis.example/claim",
             "Oferta por tiempo limitado. Ingrese tarjeta, fecha de vencimiento y codigo de seguridad."),
            ("Documento compartido", "http://docs.example-share.co/login",
             "Tiene un documento privado. Inicie sesion nuevamente para verlo antes de que expire."),
            ("Multa pendiente", "http://gobierno.example-pagos.biz",
             "Pague su multa hoy para evitar cargos adicionales. Complete sus datos bancarios."),
            ("Confirmacion inusual", "http://paypal.example-security-alert.com",
             "Confirmacion requerida: su cuenta presenta intentos de acceso desde otro pais."),
        ]

        rows = []
        for subject, url, body in legitimate:
            rows.append({"subject": subject, "url": url, "body": body, "label": 0})
            rows.append({
                "subject": subject,
                "url": url,
                "body": body + " Para mayor seguridad, escriba la dirección oficial en el navegador.",
                "label": 0,
            })
        for subject, url, body in phishing:
            rows.append({"subject": subject, "url": url, "body": body, "label": 1})
            rows.append({
                "subject": subject,
                "url": url,
                "body": body + " Esta acción es obligatoria y el enlace vence hoy.",
                "label": 1,
            })
            rows.append({
                "subject": subject,
                "url": url.replace("http://", "http://login-"),
                "body": body,
                "label": 1,
            })
        return rows

