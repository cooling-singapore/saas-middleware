import logging
import smtplib
import ssl
from typing import Optional

from saas.keystore.keystore import Keystore

logger = logging.getLogger('email.service')


class EmailService:
    def __init__(self, keystore: Keystore) -> None:
        self._keystore = keystore

    def _create_smtp_session(self) -> Optional[smtplib.SMTP]:
        # do we have SMTP credentials at all?
        if not self._keystore.has_asset('smtp-credentials'):
            logger.warning(f"no SMTP credentials found.")
            return None

        # do we have the credentials for the email address used?
        asset = self._keystore.get_asset('smtp-credentials')
        credentials = asset.get(self._keystore.identity.email)
        if not credentials:
            logger.warning(f"no SMTP credentials found for '{self._keystore.identity.email}'.")
            return None

        # try to establish a session
        try:
            address = credentials.server.split(":")
            context = ssl.create_default_context()
            smtp = smtplib.SMTP(address[0], address[1])
            smtp.ehlo()
            smtp.starttls(context=context)
            smtp.ehlo()
            smtp.login(credentials.login, credentials.password)
            logger.debug(f"SMTP session established: email={self._keystore.identity.email} "
                         f"server={credentials.server} login={credentials.login}")
            return smtp

        except smtplib.SMTPException as e:
            logger.error(f"could not establish SMTP session: {e}")
            return None

    def _send_email(self, receiver: str, subject: str, body: str) -> bool:
        # create a SMTP session
        smtp = self._create_smtp_session()
        if smtp is not None:
            try:
                smtp.sendmail(self._keystore.identity.email, receiver,
                              f"From: {self._keystore.identity.email}\nTo: {receiver}\nSubject: {subject}\n\n{body}")
                smtp.close()
                return True

            except smtplib.SMTPException as e:
                logger.error(f"cannot send email: {e}")
                smtp.close()
                return False

        else:
            logger.warning(f"cannot send email: no SMTP session -> using stdout")
            print(f"FROM: {self._keystore.identity.email}\nTO: {receiver}\nSUBJECT: {subject}\nBODY:\n{body}")
            return True

    def send_ownership_transfer_notification_to_prev_owner(self, new_owner, prev_owner, obj_id, address):
        subject = f"Transfer of Ownership Notification"

        body = f"Dear {prev_owner.name},\n\n" \
               f"This is to inform you that the ownership of a data object you own has been transferred to a " \
               f"new user.\n" \
               f"- Data Object Id: {obj_id}\n" \
               f"- New Owner: {new_owner.name} <{new_owner.email}>\n" \
               f"- DOR Address: {address}\n\n"

        return self._send_email(prev_owner.email, subject, body)

    def send_ownership_transfer_notification_to_new_owner(self, new_owner, prev_owner, obj_id, address, request=None):
        subject = f"Transfer of Ownership Notification"

        body = f"Dear {new_owner.name},\n\n" \
               f"This is to inform you that the ownership of a data object has been transferred to you.\n" \
               f"- Data Object Id: {obj_id}\n" \
               f"- Previous Owner: {prev_owner.name} <{prev_owner.email}>\n" \
               f"- DOR Address: {address}\n\n"

        # does the new owner have to import the content key?
        if request is not None:
            body += f"The data object is encrypted. Use the SaaS CLI to import the content key for this data object " \
                    f"into your keystore:\n" \
                    f"saas_cli request\n\n"

            body += f"Request Content (when asked by the CLI, simply copy and paste the following):\n" \
                    f"{request}\n\n" \

        return self._send_email(new_owner.email, subject, body)

    def send_content_key_request(self, owner, obj_id, user, address, request):
        subject = f"Request for Content Key"

        body = f"Dear {owner.name},\n\n" \
               f"You have a pending request for the content key of one of your data objects. This request has been " \
               f"auto-generated by an RTI instance on behalf of a user who wants to process the contents of your " \
               f"data object.\n" \
               f"- Data Object Id: {obj_id}\n" \
               f"- Requesting User: {user.name} <{user.email}>\n" \
               f"- RTI Address: {address}\n\n"

        body += f"Use the SaaS CLI to accept or reject this request. Carefully review and follow the instructions" \
                f"provided by the SaaS CLI:\n" \
                f"saas_cli request\n\n"

        body += f"Request Content (when asked by the CLI, simply copy and paste the following):\n" \
                f"{request}\n\n" \

        return self._send_email(owner.email, subject, body)

    def send_test_email(self, receiver):
        return self._send_email(receiver, "Test Email", "This is a test email.")
