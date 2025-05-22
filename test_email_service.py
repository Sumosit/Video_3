import pytest
from unittest.mock import patch, MagicMock
from email_service import EmailService

class TestEmailService:

    @patch('smtplib.SMTP')
    def test_send_email_success(self, mock_smtp):
        # Arrange
        mock_server = MagicMock()
        mock_smtp.return_value.__enter__.return_value = mock_server
        email_service = EmailService(smtp_server='smtp.test.com', smtp_port=587, username='user', password='pass')
        subject = 'Test Subject'
        body = 'Test Body'
        recipient = 'recipient@example.com'

        # Act
        email_service.send_email(recipient, subject, body)

        # Assert
        mock_smtp.assert_called_with('smtp.test.com', 587)
        mock_server.starttls.assert_called_once()
        mock_server.login.assert_called_with('user', 'pass')
        mock_server.sendmail.assert_called_once_with(
            'user',
            recipient,
            f"Subject: {subject}\n\n{body}"
        )
        mock_server.quit.assert_not_called()  # Because using context manager

    @patch('smtplib.SMTP')
    def test_send_email_failure(self, mock_smtp):
        # Arrange
        mock_server = MagicMock()
        mock_server.sendmail.side_effect = Exception('SMTP error')
        mock_smtp.return_value.__enter__.return_value = mock_server
        email_service = EmailService(smtp_server='smtp.test.com', smtp_port=587, username='user', password='pass')
        recipient = 'recipient@example.com'
        subject = 'Test Subject'
        body = 'Test Body'

        # Act & Assert
        with pytest.raises(Exception) as excinfo:
            email_service.send_email(recipient, subject, body)
        assert 'SMTP error' in str(excinfo.value)
        mock_server.starttls.assert_called_once()
        mock_server.login.assert_called_with('user', 'pass')
        mock_server.sendmail.assert_called_once()

    @patch('smtplib.SMTP')
    def test_send_email_with_custom_headers(self, mock_smtp):
        # Arrange
        mock_server = MagicMock()
        mock_smtp.return_value.__enter__.return_value = mock_server
        email_service = EmailService(smtp_server='smtp.test.com', smtp_port=587, username='user', password='pass')
        recipient = 'recipient@example.com'
        subject = 'Test Subject'
        body = 'Test Body'
        headers = {'X-Custom-Header': 'Value'}

        # Act
        email_service.send_email(recipient, subject, body, headers=headers)

        # Assert
        mock_server.sendmail.assert_called_once()
        args, kwargs = mock_server.sendmail.call_args
        email_content = args[2]
        assert f'Subject: {subject}' in email_content
        assert 'X-Custom-Header: Value' in email_content
