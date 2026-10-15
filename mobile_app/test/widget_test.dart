import 'package:flutter_test/flutter_test.dart';
import 'package:phishing_toolkit_mobile/main.dart';

void main() {
  testWidgets('Phishing Analysis Toolkit dashboard loads', (tester) async {
    await tester.pumpWidget(const PhishingToolkitApp());
    expect(find.text('Phishing Analysis Toolkit'), findsWidgets);
  });
}
