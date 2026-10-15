import 'dart:convert';

import 'package:file_picker/file_picker.dart';

import 'package:flutter/material.dart';
import 'package:http/http.dart' as http;

void main() {
  runApp(const PhishingToolkitApp());
}

const Color bg = Color(0xFF111315);
const Color bgSoft = Color(0xFF151719);
const Color surface = Color(0xFF191C1F);
const Color surfaceRaised = Color(0xFF202427);
const Color border = Color(0xFF303438);
const Color borderSoft = Color(0xFF272B2E);
const Color borderStrong = Color(0xFF3B4044);
const Color textPrimary = Color(0xFFF1EEE7);
const Color textSecondary = Color(0xFFC1BDB4);
const Color textMuted = Color(0xFF94918A);
const Color textFaint = Color(0xFF696762);
const Color accent = Color(0xFFD6A84F);
const Color accentSoft = Color(0x1FD6A84F);
const Color success = Color(0xFF6F9B7A);
const Color warning = Color(0xFFD6A84F);
const Color danger = Color(0xFFC96A62);
const Color info = Color(0xFF8D9BA5);
const Color infoSoft = Color(0x1F8D9BA5);

class PhishingToolkitApp extends StatelessWidget {
  const PhishingToolkitApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Phishing Analysis Toolkit',
      debugShowCheckedModeBanner: false,
      theme: ThemeData(
        useMaterial3: true,
        brightness: Brightness.dark,
        scaffoldBackgroundColor: bg,
        colorScheme: const ColorScheme.dark(
          primary: accent,
          secondary: success,
          surface: surface,
          error: danger,
          onPrimary: bg,
          onSecondary: bg,
          onSurface: textPrimary,
          onError: textPrimary,
        ),
        appBarTheme: const AppBarTheme(
          backgroundColor: surface,
          foregroundColor: textPrimary,
          elevation: 0,
          scrolledUnderElevation: 0,
        ),
        cardTheme: CardThemeData(
          color: surface,
          elevation: 0,
          margin: EdgeInsets.zero,
          shape: RoundedRectangleBorder(
            borderRadius: BorderRadius.circular(10),
            side: const BorderSide(color: border),
          ),
        ),
        inputDecorationTheme: InputDecorationTheme(
          filled: true,
          fillColor: bgSoft,
          hintStyle: const TextStyle(color: textFaint),
          labelStyle: const TextStyle(color: textMuted),
          contentPadding: const EdgeInsets.all(14),
          border: OutlineInputBorder(
            borderRadius: BorderRadius.circular(7),
            borderSide: const BorderSide(color: border),
          ),
          enabledBorder: OutlineInputBorder(
            borderRadius: BorderRadius.circular(7),
            borderSide: const BorderSide(color: border),
          ),
          focusedBorder: OutlineInputBorder(
            borderRadius: BorderRadius.circular(7),
            borderSide: const BorderSide(color: accent, width: 1.4),
          ),
        ),
        filledButtonTheme: FilledButtonThemeData(
          style: FilledButton.styleFrom(
            backgroundColor: accent,
            foregroundColor: bg,
            elevation: 0,
            padding: const EdgeInsets.symmetric(horizontal: 18, vertical: 14),
            shape: RoundedRectangleBorder(
              borderRadius: BorderRadius.circular(7),
            ),
          ),
        ),
        outlinedButtonTheme: OutlinedButtonThemeData(
          style: OutlinedButton.styleFrom(
            foregroundColor: textSecondary,
            side: const BorderSide(color: borderStrong),
            padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12),
            shape: RoundedRectangleBorder(
              borderRadius: BorderRadius.circular(7),
            ),
          ),
        ),
        navigationBarTheme: NavigationBarThemeData(
          backgroundColor: surface,
          indicatorColor: accentSoft,
          elevation: 0,
          labelTextStyle: WidgetStateProperty.resolveWith((states) {
            return TextStyle(
              fontSize: 11,
              fontWeight: states.contains(WidgetState.selected)
                  ? FontWeight.w700
                  : FontWeight.w400,
              color: states.contains(WidgetState.selected) ? accent : textMuted,
            );
          }),
          iconTheme: WidgetStateProperty.resolveWith((states) {
            return IconThemeData(
              color: states.contains(WidgetState.selected) ? accent : textMuted,
            );
          }),
        ),
        dividerColor: borderSoft,
      ),
      home: const ToolkitHome(),
    );
  }
}

class ToolkitHome extends StatefulWidget {
  const ToolkitHome({super.key});

  @override
  State<ToolkitHome> createState() => _ToolkitHomeState();
}

class _ToolkitHomeState extends State<ToolkitHome> {
  int selectedIndex = 0;
  String analysisType = 'url';
  bool isAnalyzing = false;
  bool isLoadingHistory = false;
  bool isCheckingBackend = false;
  bool? backendConnectionSuccessful;
  String? backendConnectionStatus;
  bool obscurePassword = true;
  PlatformFile? selectedAttachment;
  bool isAnalyzingAttachment = false;
  String? attachmentError;
  String? attachmentMessage;

  final urlController = TextEditingController();
  final domainController = TextEditingController();
  final backendController = TextEditingController(
    text: 'http://127.0.0.1:5000',
  );
  final usernameController = TextEditingController();
  final passwordController = TextEditingController();

  String? analysisMessage;
  String? analysisError;
  String? historyError;
  Map<String, dynamic>? latestReport;
  String? latestReportId;
  String? latestTarget;
  String? latestType;

  List<Map<String, dynamic>> analysisHistory = [];

  final titles = const ['Dashboard', 'Link Analysis', 'Attachment Analysis', 'Reports', 'Settings'];

  @override
  void dispose() {
    urlController.dispose();
    domainController.dispose();
    backendController.dispose();
    usernameController.dispose();
    passwordController.dispose();
    super.dispose();
  }

  void showMessage(String message) {
    if (!mounted) return;
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(
        content: Text(message),
        backgroundColor: surfaceRaised,
        behavior: SnackBarBehavior.floating,
      ),
    );
  }

  String get currentTarget {
    return analysisType == 'domain'
        ? domainController.text.trim()
        : urlController.text.trim();
  }

  String get backendBaseUrl {
    return backendController.text.trim().replaceFirst(RegExp(r'/+$'), '');
  }

  bool isValidBackend(String value) {
    final uri = Uri.tryParse(value);
    return uri != null &&
        uri.hasAuthority &&
        const ['http', 'https'].contains(uri.scheme) &&
        uri.host.isNotEmpty;
  }

  Map<String, String> get requestHeaders {
    final headers = <String, String>{
      'Content-Type': 'application/json',
      'Accept': 'application/json',
    };
    final username = usernameController.text;
    final password = passwordController.text;
    if (username.isNotEmpty || password.isNotEmpty) {
      headers['Authorization'] =
          'Basic ${base64Encode(utf8.encode('$username:$password'))}';
    }
    return headers;
  }

  Future<void> fetchAnalysisHistory() async {
    if (isLoadingHistory) return;

    if (!isValidBackend(backendBaseUrl)) {
      setState(() {
        historyError = 'Check the backend URL in Settings.';
      });
      return;
    }

    setState(() {
      isLoadingHistory = true;
      historyError = null;
    });

    try {
      final response = await http
          .get(
            Uri.parse('$backendBaseUrl/api/irt/overview'),
            headers: requestHeaders,
          )
          .timeout(const Duration(seconds: 30));

      dynamic decoded;
      try {
        decoded = jsonDecode(response.body);
      } on FormatException {
        throw Exception(
          'The backend returned a non-JSON history response (HTTP ${response.statusCode}).',
        );
      }

      if (response.statusCode != 200) {
        final message = decoded is Map
            ? decoded['message']?.toString()
            : null;
        throw Exception(
          message ?? 'History request failed (${response.statusCode}).',
        );
      }

      if (decoded is! Map ||
          decoded['status'] != 'ok' ||
          decoded['recent_analyses'] is! List) {
        throw Exception('The backend returned an unexpected history response.');
      }

      final records = (decoded['recent_analyses'] as List)
          .whereType<Map>()
          .map((record) => Map<String, dynamic>.from(record))
          .toList();

      if (!mounted) return;
      setState(() {
        analysisHistory = records;
        historyError = null;
      });
    } catch (error) {
      if (!mounted) return;
      setState(() {
        historyError = error.toString().replaceFirst('Exception: ', '');
      });
    } finally {
      if (mounted) {
        setState(() {
          isLoadingHistory = false;
        });
      }
    }
  }

  Future<void> analyzeTarget() async {
    final isDomain = analysisType == 'domain';
    final value = currentTarget;

    if (value.isEmpty) {
      setState(() {
        analysisError = isDomain
            ? 'Enter a domain to analyze.'
            : 'Enter a URL to analyze.';
        analysisMessage = null;
      });
      return;
    }

    if (isDomain) {
      final normalized = value.endsWith('.')
          ? value.substring(0, value.length - 1)
          : value;
      final domainPattern = RegExp(
        r'^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)(?:\.(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?))*$',
      );
      if (!domainPattern.hasMatch(normalized) || !normalized.contains('.')) {
        setState(() {
          analysisError = 'Enter a valid domain, such as example.com.';
          analysisMessage = null;
        });
        return;
      }
    } else {
      final uri = Uri.tryParse(value);
      if (uri == null ||
          !uri.hasAuthority ||
          !const ['http', 'https'].contains(uri.scheme) ||
          uri.host.isEmpty ||
          value.length > 4096) {
        setState(() {
          analysisError =
              'Enter a valid HTTP or HTTPS URL no longer than 4096 characters.';
          analysisMessage = null;
        });
        return;
      }
    }

    if (!isValidBackend(backendBaseUrl)) {
      setState(() {
        analysisError = 'Check the backend URL in Settings.';
        analysisMessage = null;
      });
      return;
    }

    setState(() {
      isAnalyzing = true;
      analysisError = null;
      analysisMessage = null;
    });

    try {
      final endpoint = isDomain ? 'domain' : 'url';
      final payload = isDomain ? {'domain': value} : {'url': value};
      final response = await http
          .post(
            Uri.parse('$backendBaseUrl/api/analyze/$endpoint'),
            headers: requestHeaders,
            body: jsonEncode(payload),
          )
          .timeout(const Duration(seconds: 90));

      dynamic decoded;
      try {
        decoded = jsonDecode(response.body);
      } on FormatException {
        if (response.statusCode == 401 || response.statusCode == 403) {
          throw Exception(
            'Authentication failed. Check the backend credentials in Settings.',
          );
        }
        if (response.statusCode == 404) {
          throw Exception(
            'The API endpoint was not found. Check the backend URL and Flask routes.',
          );
        }
        throw const FormatException(
          'The backend returned a non-JSON response.',
        );
      }

      if (decoded is! Map<String, dynamic>) {
        throw const FormatException('Unexpected response from the backend.');
      }

      if (response.statusCode == 401 || response.statusCode == 403) {
        throw Exception(
          decoded['message']?.toString() ??
              'Authentication failed. Check the backend credentials.',
        );
      }

      if (response.statusCode != 200 || decoded['status'] != 'ok') {
        throw Exception(
          decoded['message']?.toString() ??
              'Analysis failed with HTTP ${response.statusCode}.',
        );
      }

      final report = decoded['report'];
      if (report is! Map<String, dynamic>) {
        throw const FormatException(
          'The response did not contain a valid report.',
        );
      }

      final findings = report['findings'];
      final findingLines = <String>[];
      if (findings is List) {
        for (final finding in findings.take(5)) {
          if (finding is Map) {
            final description = finding['description'] ??
                finding['title'] ??
                finding['name'] ??
                finding['message'];
            if (description != null) {
              findingLines.add('- $description');
            }
          }
        }
      }

      final reportId = decoded['report_id']?.toString();
      final summary = StringBuffer()
        ..writeln('${isDomain ? 'Domain' : 'URL'} analysis complete')
        ..writeln('Target: $value')
        ..writeln('Verdict: ${report['verdict'] ?? 'Unknown'}')
        ..writeln('Risk score: ${report['risk_score'] ?? 'N/A'}/100')
        ..writeln(
          'Findings: ${report['finding_count'] ?? (findings is List ? findings.length : 0)}',
        );

      if (reportId != null) {
        summary.writeln('Report ID: $reportId');
      }
      if (findingLines.isNotEmpty) {
        summary
          ..writeln()
          ..writeln('Key findings:')
          ..write(findingLines.join('\n'));
      }

      if (!mounted) return;
      setState(() {
        analysisMessage = summary.toString().trim();
        latestReport = Map<String, dynamic>.from(report);
        latestReportId = reportId;
        latestTarget = value;
        latestType = isDomain ? 'Domain' : 'URL';
      });
      await fetchAnalysisHistory();
    } on http.ClientException {
      if (!mounted) return;
      setState(() {
        analysisError =
            'Could not reach Flask. Check that the server is running and that the configured backend address is reachable from this device.';
      });
    } on FormatException {
      if (!mounted) return;
      setState(() {
        analysisError =
            'The backend returned an unexpected response. Check the Flask server logs.';
      });
    } catch (error) {
      if (!mounted) return;
      setState(() {
        analysisError = error.toString().replaceFirst('Exception: ', '');
      });
    } finally {
      if (mounted) {
        setState(() {
          isAnalyzing = false;
        });
      }
    }
  }

  Future<void> validateBackendUrl() async {
    if (isCheckingBackend) return;

    if (!isValidBackend(backendBaseUrl)) {
      setState(() {
        backendConnectionSuccessful = false;
        backendConnectionStatus = 'Enter a valid HTTP or HTTPS backend URL.';
      });
      showMessage('Enter a valid HTTP or HTTPS backend URL.');
      return;
    }

    setState(() {
      isCheckingBackend = true;
      backendConnectionSuccessful = null;
      backendConnectionStatus = 'Testing connection to the backend...';
    });

    try {
      final response = await http
          .get(
            Uri.parse('$backendBaseUrl/health'),
            headers: requestHeaders,
          )
          .timeout(const Duration(seconds: 8));

      dynamic decoded;
      try {
        decoded = jsonDecode(response.body);
      } on FormatException {
        decoded = null;
      }

      final healthy = response.statusCode == 200 &&
          decoded is Map &&
          decoded['status'] == 'ok';

      if (!mounted) return;

      setState(() {
        backendConnectionSuccessful = healthy;
        backendConnectionStatus = healthy
            ? 'Connected successfully. Flask health check passed.'
            : 'Server responded with HTTP ${response.statusCode}, but the health check failed.';
      });

      showMessage(
        healthy
            ? 'Backend connection successful.'
            : 'Backend health check failed.',
      );
    } on Exception catch (error) {
      if (!mounted) return;

      final timedOut = error.toString().contains('TimeoutException');
      setState(() {
        backendConnectionSuccessful = false;
        backendConnectionStatus = timedOut
            ? 'Connection timed out. Check that Flask is running.'
            : 'Connection failed. Check the backend URL, server and USB forwarding.';
      });
      showMessage(backendConnectionStatus!);
    } finally {
      if (mounted) {
        setState(() {
          isCheckingBackend = false;
        });
      }
    }
  }

  Widget buildHeaderLabel(String title, String subtitle) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(
          title,
          style: const TextStyle(
            color: textPrimary,
            fontSize: 27,
            fontWeight: FontWeight.w500,
            letterSpacing: -0.6,
          ),
        ),
        const SizedBox(height: 8),
        Text(
          subtitle,
          style: const TextStyle(color: textMuted, fontSize: 13, height: 1.7),
        ),
      ],
    );
  }

  Widget buildSectionLabel(String title) => SectionHeading(title: title);

  Widget buildStatusCard() {
    final statusText = isCheckingBackend
        ? 'Checking connection to Flask...'
        : backendConnectionStatus ??
            'Connection status has not been checked.';
    final statusColor = isCheckingBackend
        ? warning
        : backendConnectionSuccessful == true
            ? accent
            : backendConnectionSuccessful == false
                ? Colors.redAccent
                : warning;

    return Container(
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: surface,
        border: Border.all(color: border),
        borderRadius: BorderRadius.circular(10),
      ),
      child: Row(
        children: [
          Icon(Icons.dns_outlined, color: statusColor, size: 22),
          const SizedBox(width: 12),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                const Text(
                  'Backend configuration',
                  style: TextStyle(
                    color: textPrimary,
                    fontSize: 13,
                    fontWeight: FontWeight.w600,
                  ),
                ),
                const SizedBox(height: 5),
                Text(
                  statusText,
                  style: TextStyle(color: statusColor, fontSize: 12),
                ),
              ],
            ),
          ),
          IconButton(
            onPressed: () => setState(() => selectedIndex = 4),
            icon: const Icon(Icons.chevron_right, color: textMuted),
          ),
        ],
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
        final pages = [
      dashboardPage(),
      analyzePage(),
      attachmentPage(),
      reportsPage(),
      settingsPage(),
    ];
    return Scaffold(
      appBar: AppBar(
        title: Row(
          children: [
            Container(
              width: 38,
              height: 38,
              alignment: Alignment.center,
              decoration: BoxDecoration(
                color: accentSoft,
                border: Border.all(color: const Color(0x59D6A84F)),
                borderRadius: BorderRadius.circular(7),
              ),
              child: const Icon(Icons.shield_outlined, color: accent, size: 22),
            ),
            const SizedBox(width: 12),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  const Text(
                    'Phishing Analysis Toolkit',
                    maxLines: 1,
                    overflow: TextOverflow.ellipsis,
                    style: TextStyle(
                      color: textPrimary,
                      fontSize: 13,
                      fontWeight: FontWeight.w800,
                      letterSpacing: 1.1,
                    ),
                  ),
                  const SizedBox(height: 3),
                  Text(
                    titles[selectedIndex],
                    style: const TextStyle(color: textMuted, fontSize: 11),
                  ),
                ],
              ),
            ),
          ],
        ),
      ),
      body: SafeArea(
        child: IndexedStack(index: selectedIndex, children: pages),
      ),
            bottomNavigationBar: NavigationBar(
        selectedIndex: selectedIndex,
        onDestinationSelected: (index) {
          setState(() => selectedIndex = index);
          if (index == 3) {
            fetchAnalysisHistory();
          }
        },
        destinations: const [
          NavigationDestination(
            icon: Icon(Icons.dashboard_outlined),
            selectedIcon: Icon(Icons.dashboard),
            label: 'Home',
          ),
          NavigationDestination(
            icon: Icon(Icons.manage_search_outlined),
            selectedIcon: Icon(Icons.manage_search),
            label: 'Links',
          ),
          NavigationDestination(
            icon: Icon(Icons.attach_file_outlined),
            selectedIcon: Icon(Icons.attach_file),
            label: 'Files',
          ),
          NavigationDestination(
            icon: Icon(Icons.description_outlined),
            selectedIcon: Icon(Icons.description),
            label: 'Reports',
          ),
          NavigationDestination(
            icon: Icon(Icons.settings_outlined),
            selectedIcon: Icon(Icons.settings),
            label: 'Settings',
          ),
        ],
      ),
    );
  }

  Widget dashboardPage() {
    return ListView(
      padding: const EdgeInsets.all(20),
      children: [
        Container(
          padding: const EdgeInsets.fromLTRB(22, 24, 22, 22),
          decoration: BoxDecoration(
            color: surface,
            border: Border.all(color: border),
            borderRadius: BorderRadius.circular(10),
          ),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              const Text(
                'CYBERSECURITY / THREAT INVESTIGATION',
                style: TextStyle(
                  color: accent,
                  fontSize: 10,
                  fontWeight: FontWeight.w700,
                  letterSpacing: 1.4,
                ),
              ),
              const SizedBox(height: 18),
              const Text(
                'Phishing Analysis Toolkit',
                style: TextStyle(
                  color: textPrimary,
                  fontSize: 28,
                  height: 1.15,
                  fontWeight: FontWeight.w500,
                  letterSpacing: -0.8,
                ),
              ),
              const SizedBox(height: 12),
              const Text(
                'Investigate suspicious URLs and domains, review security indicators, and examine the results returned by your Flask analysis engine.',
                style: TextStyle(color: textMuted, fontSize: 13, height: 1.7),
              ),
              const SizedBox(height: 24),
              SizedBox(
                width: double.infinity,
                child: FilledButton.icon(
                  onPressed: () => setState(() => selectedIndex = 1),
                  icon: const Icon(Icons.search, size: 18),
                  label: const Text('Start an investigation'),
                ),
              ),
            ],
          ),
        ),
        const SizedBox(height: 28),
        buildSectionLabel('WORKSPACE STATUS'),
        const SizedBox(height: 12),
        buildStatusCard(),
        const SizedBox(height: 28),
        buildSectionLabel('INVESTIGATION TOOLS'),
        const SizedBox(height: 12),
        Row(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Expanded(
              child: ToolCard(
                icon: Icons.link,
                title: 'URL Analysis',
                subtitle: 'Inspect a web address',
                onTap: () {
                  setState(() {
                    analysisType = 'url';
                    selectedIndex = 1;
                  });
                },
              ),
            ),
            const SizedBox(width: 12),
            Expanded(
              child: ToolCard(
                icon: Icons.language,
                title: 'Domain Analysis',
                subtitle: 'Inspect domain indicators',
                onTap: () {
                  setState(() {
                    analysisType = 'domain';
                    selectedIndex = 1;
                  });
                },
              ),
            ),
          ],
        ),
        const SizedBox(height: 12),
        ToolCard(
          icon: Icons.folder_open_outlined,
          title: 'Analysis Reports',
          subtitle: 'Review recent saved analysis results',
          onTap: () {
                        setState(() => selectedIndex = 3);
            fetchAnalysisHistory();
          },
        ),
        const SizedBox(height: 28),
        buildSectionLabel('ANALYST NOTE'),
        const SizedBox(height: 12),
        Container(
          padding: const EdgeInsets.all(16),
          decoration: BoxDecoration(
            color: bgSoft,
            border: Border.all(color: borderSoft),
            borderRadius: BorderRadius.circular(7),
          ),
          child: const Row(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Icon(Icons.info_outline, color: info, size: 20),
              SizedBox(width: 12),
              Expanded(
                child: Text(
                  'An analysis verdict is one piece of evidence, not a guarantee. Review findings and corroborate them before making security decisions.',
                  style: TextStyle(
                    color: textSecondary,
                    fontSize: 12,
                    height: 1.7,
                  ),
                ),
              ),
            ],
          ),
        ),
      ],
    );
  }

  Future<void> pickAttachment() async {
    try {
      final file = await FilePicker.pickFile();

      if (file == null || !mounted) {
        return;
      }

      final fileSize = file.lengthSync() ?? 0;

      if (fileSize > 25 * 1024 * 1024) {
        setState(() {
          attachmentError = 'File exceeds the 25 MB upload limit.';
          attachmentMessage = null;
        });
        return;
      }

      setState(() {
        selectedAttachment = file;
        attachmentError = null;
        attachmentMessage = null;
      });
    } catch (_) {
      if (!mounted) return;

      setState(() {
        attachmentError = 'Could not open the file picker. Please try again.';
        attachmentMessage = null;
      });
    }
  }

  Future<void> analyzeAttachment() async {
    final file = selectedAttachment;

    if (file == null) {
      setState(() {
        attachmentError = 'Choose a file before starting the analysis.';
      });
      return;
    }

    if (!isValidBackend(backendBaseUrl)) {
      setState(() {
        attachmentError = 'Enter a valid Flask backend URL in Settings.';
      });
      return;
    }


    setState(() {
      isAnalyzingAttachment = true;
      attachmentError = null;
      attachmentMessage = null;
    });

    try {
      final fileBytes = await file.readAsBytes();
      final request = http.MultipartRequest(
        'POST',
        Uri.parse('$backendBaseUrl/api/analyze/attachment'),
      );

      request.headers['Accept'] = 'application/json';

      final username = usernameController.text;
      final password = passwordController.text;

      if (username.isNotEmpty || password.isNotEmpty) {
        request.headers['Authorization'] =
            'Basic ${base64Encode(utf8.encode('$username:$password'))}';
      }

      request.files.add(
        http.MultipartFile.fromBytes(
          'attachment_file',
          fileBytes,
          filename: file.name,
        ),
      );

      final streamedResponse = await request
          .send()
          .timeout(const Duration(seconds: 120));

      final response = await http.Response.fromStream(streamedResponse);

      dynamic decoded;

      try {
        decoded = jsonDecode(response.body);
      } on FormatException {
        throw Exception(
          'The backend returned an unreadable response (${response.statusCode}).',
        );
      }

      if (response.statusCode == 401 || response.statusCode == 403) {
        throw Exception(
          'Authentication failed. Check the backend credentials in Settings.',
        );
      }

      if (decoded is! Map<String, dynamic>) {
        throw Exception('The backend returned an unexpected response.');
      }

      if (response.statusCode != 200 || decoded['status'] != 'ok') {
        throw Exception(
          decoded['message']?.toString() ?? 'Attachment analysis failed.',
        );
      }

      final report = decoded['report'];

      if (report is! Map) {
        throw Exception('The backend response did not contain a valid report.');
      }

      if (!mounted) return;

      setState(() {
        latestReport = Map<String, dynamic>.from(report);
        latestReportId = decoded['report_id']?.toString();
        latestTarget = file.name;
        latestType = 'Attachment';
        attachmentMessage = 'Attachment analysis completed.';
        selectedIndex = 4;
      });

      await fetchAnalysisHistory();
    } on Exception catch (error) {
      if (!mounted) return;

      final message = error.toString().replaceFirst('Exception: ', '');

      setState(() {
        attachmentError = message;
      });
    } catch (_) {
      if (!mounted) return;

      setState(() {
        attachmentError =
            'Could not reach the Flask backend. Check the backend URL and connection.';
      });
    } finally {
      if (mounted) {
        setState(() {
          isAnalyzingAttachment = false;
        });
      }
    }
  }


  Widget analyzePage() {
    final isDomain = analysisType == 'domain';

    return ListView(
      padding: const EdgeInsets.all(20),
      children: [
        const Text(
          'NEW INVESTIGATION',
          style: TextStyle(
            color: accent,
            fontSize: 10,
            fontWeight: FontWeight.w700,
            letterSpacing: 1.5,
          ),
        ),
        const SizedBox(height: 10),
        buildHeaderLabel(
          isDomain ? 'Domain Analysis' : 'URL Analysis',
          isDomain
              ? 'Submit a domain to the Flask domain-analysis endpoint.'
              : 'Submit a complete HTTP or HTTPS URL to the Flask analysis endpoint.',
        ),
        const SizedBox(height: 24),
        Container(
          padding: const EdgeInsets.all(18),
          decoration: BoxDecoration(
            color: surface,
            border: Border.all(color: border),
            borderRadius: BorderRadius.circular(10),
          ),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              SegmentedButton<String>(
                segments: const [
                  ButtonSegment<String>(
                    value: 'url',
                    label: Text('URL'),
                    icon: Icon(Icons.link),
                  ),
                  ButtonSegment<String>(
                    value: 'domain',
                    label: Text('Domain'),
                    icon: Icon(Icons.language),
                  ),
                ],
                selected: {analysisType},
                onSelectionChanged: isAnalyzing
                    ? null
                    : (selection) {
                        setState(() {
                          analysisType = selection.first;
                          analysisError = null;
                          analysisMessage = null;
                        });
                      },
              ),
              const SizedBox(height: 24),
              SectionHeading(title: isDomain ? 'TARGET DOMAIN' : 'TARGET URL'),
              const SizedBox(height: 14),
              TextField(
                key: ValueKey(analysisType),
                controller: isDomain ? domainController : urlController,
                keyboardType: TextInputType.url,
                autocorrect: false,
                enableSuggestions: false,
                textInputAction: TextInputAction.go,
                decoration: InputDecoration(
                  hintText: isDomain ? 'example.com' : 'https://example.com',
                  prefixIcon: Icon(
                    isDomain ? Icons.language : Icons.link,
                    color: textMuted,
                  ),
                ),
                onSubmitted: (_) {
                  if (!isAnalyzing) analyzeTarget();
                },
              ),
              const SizedBox(height: 16),
              SizedBox(
                width: double.infinity,
                child: FilledButton.icon(
                  onPressed: isAnalyzing ? null : analyzeTarget,
                  icon: isAnalyzing
                      ? const SizedBox(
                          width: 18,
                          height: 18,
                          child: CircularProgressIndicator(strokeWidth: 2),
                        )
                      : const Icon(Icons.manage_search),
                  label: Text(
                    isAnalyzing
                        ? 'Analyzing...'
                        : isDomain
                            ? 'Analyze Domain'
                            : 'Analyze URL',
                  ),
                ),
              ),
              if (analysisError != null) ...[
                const SizedBox(height: 16),
                ResultPanel(
                  icon: Icons.error_outline,
                  color: danger,
                  message: analysisError!,
                ),
              ],
              if (analysisMessage != null) ...[
                const SizedBox(height: 16),
                ResultPanel(
                  icon: Icons.fact_check_outlined,
                  color: info,
                  message: analysisMessage!,
                ),
              ],
            ],
          ),
        ),
        const SizedBox(height: 18),
        Container(
          padding: const EdgeInsets.all(16),
          decoration: BoxDecoration(
            color: infoSoft,
            border: Border.all(color: border),
            borderRadius: BorderRadius.circular(7),
          ),
          child: const Row(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Icon(Icons.info_outline, color: info),
              SizedBox(width: 12),
              Expanded(
                child: Text(
                  'The application sends your target to the configured Flask API. Review its verdict and findings as investigative evidence, not as a guarantee that a target is safe.',
                  style: TextStyle(
                    color: textSecondary,
                    fontSize: 12,
                    height: 1.7,
                  ),
                ),
              ),
            ],
          ),
        ),
      ],
    );
  }

  Widget attachmentPage() {
    final file = selectedAttachment;
    final fileSizeBytes = file?.lengthSync() ?? 0;
    final fileSize = file == null
        ? ''
        : fileSizeBytes >= 1024 * 1024
            ? '${(fileSizeBytes / (1024 * 1024)).toStringAsFixed(2)} MB'
            : '${(fileSizeBytes / 1024).toStringAsFixed(1)} KB';

    return ListView(
      padding: const EdgeInsets.all(20),
      children: [
        buildSectionLabel('ATTACHMENT INVESTIGATION'),
        const SizedBox(height: 10),
        const Text(
          'Analyze a suspicious email attachment or document using your configured Flask backend.',
          style: TextStyle(
            color: textMuted,
            fontSize: 14,
            height: 1.6,
          ),
        ),
        const SizedBox(height: 24),
        Container(
          padding: const EdgeInsets.all(20),
          decoration: BoxDecoration(
            color: surface,
            borderRadius: BorderRadius.circular(18),
            border: Border.all(color: border),
          ),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Container(
                width: 54,
                height: 54,
                decoration: BoxDecoration(
                  color: accentSoft,
                  borderRadius: BorderRadius.circular(14),
                ),
                child: const Icon(
                  Icons.attach_file_rounded,
                  color: accent,
                  size: 28,
                ),
              ),
              const SizedBox(height: 18),
              const Text(
                'Select a file',
                style: TextStyle(
                  color: textPrimary,
                  fontSize: 20,
                  fontWeight: FontWeight.bold,
                ),
              ),
              const SizedBox(height: 8),
              const Text(
                'Choose a file from your device. The upload limit is 25 MB, and the backend upload policy determines which file types are accepted.',
                style: TextStyle(
                  color: textMuted,
                  fontSize: 13,
                  height: 1.5,
                ),
              ),
              const SizedBox(height: 20),
              OutlinedButton.icon(
                onPressed: isAnalyzingAttachment ? null : pickAttachment,
                icon: const Icon(Icons.folder_open_rounded),
                label: Text(file == null ? 'Choose attachment' : 'Choose another file'),
              ),
              if (file != null) ...[
                const SizedBox(height: 16),
                Container(
                  padding: const EdgeInsets.all(14),
                  decoration: BoxDecoration(
                    color: surfaceRaised,
                    borderRadius: BorderRadius.circular(12),
                    border: Border.all(color: border),
                  ),
                  child: Row(
                    children: [
                      const Icon(
                        Icons.insert_drive_file_outlined,
                        color: accent,
                        size: 30,
                      ),
                      const SizedBox(width: 12),
                      Expanded(
                        child: Column(
                          crossAxisAlignment: CrossAxisAlignment.start,
                          children: [
                            Text(
                              file.name,
                              style: const TextStyle(
                                color: textPrimary,
                                fontWeight: FontWeight.w600,
                              ),
                            ),
                            const SizedBox(height: 4),
                            Text(
                              fileSize,
                              style: const TextStyle(
                                color: textMuted,
                                fontSize: 12,
                              ),
                            ),
                          ],
                        ),
                      ),
                      IconButton(
                        tooltip: 'Remove selected file',
                        onPressed: isAnalyzingAttachment
                            ? null
                            : () {
                                setState(() {
                                  selectedAttachment = null;
                                  attachmentError = null;
                                  attachmentMessage = null;
                                });
                              },
                        icon: const Icon(
                          Icons.close_rounded,
                          color: textMuted,
                        ),
                      ),
                    ],
                  ),
                ),
              ],
              const SizedBox(height: 20),
              SizedBox(
                width: double.infinity,
                child: FilledButton.icon(
                  onPressed: file == null || isAnalyzingAttachment
                      ? null
                      : analyzeAttachment,
                  icon: isAnalyzingAttachment
                      ? const SizedBox(
                          width: 18,
                          height: 18,
                          child: CircularProgressIndicator(
                            strokeWidth: 2,
                          ),
                        )
                      : const Icon(Icons.manage_search_rounded),
                  label: Text(
                    isAnalyzingAttachment
                        ? 'Analyzing attachment...'
                        : 'Analyze attachment',
                  ),
                ),
              ),
              if (attachmentError != null) ...[
                const SizedBox(height: 16),
                ResultPanel(
                  icon: Icons.error_outline,
                  color: danger,
                  message: attachmentError!,
                ),
              ],
              if (attachmentMessage != null) ...[
                const SizedBox(height: 16),
                ResultPanel(
                  icon: Icons.check_circle_outline,
                  color: success,
                  message: attachmentMessage!,
                ),
              ],
            ],
          ),
        ),
      ],
    );
  }
  Widget reportsPage() {
    final report = latestReport;
    final findings = report?['findings'];

    return ListView(
      padding: const EdgeInsets.all(20),
      children: [
        const Text(
          'INVESTIGATION RECORDS',
          style: TextStyle(
            color: accent,
            fontSize: 10,
            fontWeight: FontWeight.w700,
            letterSpacing: 1.5,
          ),
        ),
        const SizedBox(height: 10),
        buildHeaderLabel(
          'Analysis Reports',
          'Review the latest result and saved analyses from the Flask database.',
        ),
        const SizedBox(height: 24),
        if (report == null)
          Container(
            padding: const EdgeInsets.all(28),
            decoration: BoxDecoration(
              color: surface,
              border: Border.all(color: border),
              borderRadius: BorderRadius.circular(10),
            ),
            child: const Column(
              children: [
                Icon(Icons.description_outlined, color: textMuted, size: 42),
                SizedBox(height: 16),
                Text(
                  'No reports loaded in this session',
                  style: TextStyle(
                    color: textPrimary,
                    fontSize: 15,
                    fontWeight: FontWeight.w600,
                  ),
                ),
                SizedBox(height: 8),
                Text(
                  'Saved records from the backend are listed below.',
                  textAlign: TextAlign.center,
                  style: TextStyle(color: textMuted, fontSize: 12, height: 1.6),
                ),
              ],
            ),
          )
        else ...[
          Container(
            padding: const EdgeInsets.all(18),
            decoration: BoxDecoration(
              color: surface,
              border: Border.all(color: border),
              borderRadius: BorderRadius.circular(10),
            ),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                const SectionHeading(title: 'LATEST RESULT'),
                const SizedBox(height: 14),
                Text(
                  latestType ?? 'Analysis',
                  style: const TextStyle(
                    color: accent,
                    fontSize: 12,
                    fontWeight: FontWeight.w700,
                  ),
                ),
                const SizedBox(height: 8),
                SelectableText(
                  latestTarget ?? 'Unknown target',
                  style: const TextStyle(
                    color: textPrimary,
                    fontSize: 15,
                    fontWeight: FontWeight.w600,
                  ),
                ),
                const Divider(height: 28),
                reportRow('Verdict', '${report['verdict'] ?? 'Unknown'}'),
                reportRow('Risk score', '${report['risk_score'] ?? 'N/A'}/100'),
                reportRow(
                  'Findings',
                  '${report['finding_count'] ?? (findings is List ? findings.length : 0)}',
                ),
                if (latestReportId != null)
                  reportRow('Report ID', latestReportId!),
                const SizedBox(height: 12),
                SizedBox(
                  width: double.infinity,
                  child: OutlinedButton.icon(
                    onPressed: () {
                      setState(() {
                        analysisType =
                            latestType == 'Domain' ? 'domain' : 'url';
                        if (analysisType == 'domain') {
                          domainController.text = latestTarget ?? '';
                        } else {
                          urlController.text = latestTarget ?? '';
                        }
                        selectedIndex = 1;
                      });
                    },
                    icon: const Icon(Icons.refresh),
                    label: const Text('Analyze another target'),
                  ),
                ),
              ],
            ),
          ),
          const SizedBox(height: 18),
          SectionHeading(
            title: 'FINDINGS (${findings is List ? findings.length : 0})',
          ),
          const SizedBox(height: 12),
          if (findings is List && findings.isNotEmpty)
            ...findings.map((finding) {
              final description = finding is Map
                  ? finding['description'] ??
                      finding['title'] ??
                      finding['name'] ??
                      finding['message'] ??
                      finding.toString()
                  : finding.toString();

              return Container(
                width: double.infinity,
                margin: const EdgeInsets.only(bottom: 10),
                padding: const EdgeInsets.all(14),
                decoration: BoxDecoration(
                  color: surface,
                  border: Border.all(color: border),
                  borderRadius: BorderRadius.circular(8),
                ),
                child: Text(
                  '$description',
                  style: const TextStyle(
                    color: textSecondary,
                    fontSize: 12,
                    height: 1.6,
                  ),
                ),
              );
            })
          else
            const Text(
              'No individual findings were returned in the report.',
              style: TextStyle(color: textMuted, fontSize: 12, height: 1.6),
            ),
        ],
        const SizedBox(height: 24),
        historySection(),
        const SizedBox(height: 20),
        OutlinedButton.icon(
          onPressed: () => setState(() => selectedIndex = 4),
          icon: const Icon(Icons.settings_outlined),
          label: const Text('Backend settings'),
        ),
      ],
    );
  }

  Widget historySection() {
    return Container(
      padding: const EdgeInsets.all(18),
      decoration: BoxDecoration(
        color: surface,
        border: Border.all(color: border),
        borderRadius: BorderRadius.circular(10),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              const Expanded(
                child: SectionHeading(title: 'SAVED ANALYSIS HISTORY'),
              ),
              IconButton(
                tooltip: 'Refresh history',
                onPressed: isLoadingHistory ? null : fetchAnalysisHistory,
                icon: isLoadingHistory
                    ? const SizedBox(
                        width: 18,
                        height: 18,
                        child: CircularProgressIndicator(strokeWidth: 2),
                      )
                    : const Icon(Icons.refresh, color: accent),
              ),
            ],
          ),
          const SizedBox(height: 12),
          if (historyError != null)
            ResultPanel(
              icon: Icons.error_outline,
              color: danger,
              message: historyError!,
            )
          else if (isLoadingHistory && analysisHistory.isEmpty)
            const Center(
              child: Padding(
                padding: EdgeInsets.all(20),
                child: CircularProgressIndicator(),
              ),
            )
          else if (analysisHistory.isEmpty)
            const Text(
              'No saved analyses were returned. Run an analysis and refresh.',
              style: TextStyle(color: textMuted, fontSize: 12, height: 1.6),
            )
          else
            ...analysisHistory.map((record) {
              final target = '${record['target'] ?? 'Unknown target'}';
              final verdict = '${record['verdict'] ?? 'Unknown'}';
              final risk = '${record['risk_score'] ?? 'N/A'}';
              final findings = '${record['finding_count'] ?? 0}';
              final reportId = '${record['report_id'] ?? ''}';
              final timestamp = '${record['timestamp'] ?? ''}';
              final type = '${record['analysis_type'] ?? 'Analysis'}';

              return Container(
                width: double.infinity,
                margin: const EdgeInsets.only(bottom: 12),
                padding: const EdgeInsets.all(14),
                decoration: BoxDecoration(
                  color: surfaceRaised,
                  border: Border.all(color: border),
                  borderRadius: BorderRadius.circular(8),
                ),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      type.toUpperCase(),
                      style: const TextStyle(
                        color: accent,
                        fontSize: 10,
                        fontWeight: FontWeight.w700,
                        letterSpacing: 1,
                      ),
                    ),
                    const SizedBox(height: 7),
                    SelectableText(
                      target,
                      style: const TextStyle(
                        color: textPrimary,
                        fontSize: 13,
                        fontWeight: FontWeight.w600,
                      ),
                    ),
                    const SizedBox(height: 12),
                    reportRow('Verdict', verdict),
                    reportRow('Risk score', '$risk/100'),
                    reportRow('Findings', findings),
                    if (timestamp.isNotEmpty)
                      reportRow('Timestamp', timestamp),
                    if (reportId.isNotEmpty)
                      SelectableText(
                        'Report ID: $reportId',
                        style: const TextStyle(
                          color: textMuted,
                          fontSize: 10,
                        ),
                      ),
                  ],
                ),
              );
            }),
        ],
      ),
    );
  }

  Widget reportRow(String label, String value) {
    return Padding(
      padding: const EdgeInsets.only(bottom: 12),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Expanded(
            child: Text(
              label,
              style: const TextStyle(color: textMuted, fontSize: 12),
            ),
          ),
          const SizedBox(width: 12),
          Flexible(
            child: Text(
              value,
              textAlign: TextAlign.end,
              style: const TextStyle(
                color: textPrimary,
                fontSize: 12,
                fontWeight: FontWeight.w600,
              ),
            ),
          ),
        ],
      ),
    );
  }

  Widget settingsPage() {
    return ListView(
      padding: const EdgeInsets.all(20),
      children: [
        const Text(
          'CONFIGURATION',
          style: TextStyle(
            color: accent,
            fontSize: 10,
            fontWeight: FontWeight.w700,
            letterSpacing: 1.5,
          ),
        ),
        const SizedBox(height: 10),
        buildHeaderLabel(
          'Settings',
          'Configure the Flask API used for URL and domain analysis.',
        ),
        const SizedBox(height: 24),
        Container(
          padding: const EdgeInsets.all(18),
          decoration: BoxDecoration(
            color: surface,
            border: Border.all(color: border),
            borderRadius: BorderRadius.circular(10),
          ),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              const SectionHeading(title: 'FLASK BACKEND'),
              const SizedBox(height: 14),
              const Text(
                'Backend base URL',
                style: TextStyle(color: textSecondary, fontSize: 12),
              ),
              const SizedBox(height: 8),
              TextField(
                controller: backendController,
                keyboardType: TextInputType.url,
                autocorrect: false,
                enableSuggestions: false,
                decoration: const InputDecoration(
                  hintText: 'https://your-api.example.com',
                  prefixIcon: Icon(Icons.dns_outlined, color: textMuted),
                ),
              ),
              const SizedBox(height: 20),
              const SectionHeading(title: 'OPTIONAL BASIC AUTH'),
              const SizedBox(height: 8),
              const Text(
                'Use these fields only if your Flask server requires HTTP Basic authentication. Credentials remain in app memory and are not saved by this screen.',
                style: TextStyle(color: textMuted, fontSize: 11, height: 1.6),
              ),
              const SizedBox(height: 12),
              TextField(
                controller: usernameController,
                autocorrect: false,
                enableSuggestions: false,
                decoration: const InputDecoration(
                  labelText: 'Username',
                  prefixIcon: Icon(Icons.person_outline, color: textMuted),
                ),
              ),
              const SizedBox(height: 12),
              TextField(
                controller: passwordController,
                obscureText: obscurePassword,
                autocorrect: false,
                enableSuggestions: false,
                decoration: InputDecoration(
                  labelText: 'Password',
                  prefixIcon: const Icon(Icons.lock_outline, color: textMuted),
                  suffixIcon: IconButton(
                    onPressed: () {
                      setState(() {
                        obscurePassword = !obscurePassword;
                      });
                    },
                    icon: Icon(
                      obscurePassword
                          ? Icons.visibility_outlined
                          : Icons.visibility_off_outlined,
                    ),
                  ),
                ),
              ),
              const SizedBox(height: 14),
              SizedBox(
                width: double.infinity,
                child: FilledButton(
                  onPressed: isCheckingBackend ? null : validateBackendUrl,
                  child: Text(isCheckingBackend ? 'Testing connection...' : 'Test backend connection'),
                ),
              ),
              const SizedBox(height: 12),
              const Text(
                'Test the configured Flask server using its health endpoint. Use HTTPS for remote production services.',
                style: TextStyle(color: textMuted, fontSize: 11, height: 1.6),
              ),
            ],
          ),
        ),
        const SizedBox(height: 24),
        const SectionHeading(title: 'APPLICATION'),
        const SizedBox(height: 12),
        const AboutTile(
          icon: Icons.shield_outlined,
          title: 'Phishing Analysis Toolkit',
          subtitle: 'Phishing and domain analysis interface',
        ),
        const Divider(height: 24),
        const AboutTile(
          icon: Icons.lock_outline,
          title: 'Credential security',
          subtitle:
              'Do not embed production credentials in application source code.',
        ),
        const Divider(height: 24),
        const AboutTile(
          icon: Icons.palette_outlined,
          title: 'Design system',
          subtitle:
              'Charcoal surfaces, warm amber accents, and muted green indicators.',
        ),
      ],
    );
  }
}

class SectionHeading extends StatelessWidget {
  final String title;

  const SectionHeading({super.key, required this.title});

  @override
  Widget build(BuildContext context) {
    return Text(
      title,
      style: const TextStyle(
        color: textMuted,
        fontSize: 10,
        fontWeight: FontWeight.w700,
        letterSpacing: 1.4,
      ),
    );
  }
}

class ToolCard extends StatelessWidget {
  final IconData icon;
  final String title;
  final String subtitle;
  final VoidCallback onTap;

  const ToolCard({
    super.key,
    required this.icon,
    required this.title,
    required this.subtitle,
    required this.onTap,
  });

  @override
  Widget build(BuildContext context) {
    return Card(
      child: InkWell(
        onTap: onTap,
        borderRadius: BorderRadius.circular(10),
        child: Padding(
          padding: const EdgeInsets.all(16),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Icon(icon, color: accent, size: 24),
              const SizedBox(height: 18),
              Text(
                title,
                style: const TextStyle(
                  color: textPrimary,
                  fontSize: 13,
                  fontWeight: FontWeight.w600,
                ),
              ),
              const SizedBox(height: 7),
              Text(
                subtitle,
                style: const TextStyle(
                  color: textMuted,
                  fontSize: 11,
                  height: 1.5,
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }
}

class ResultPanel extends StatelessWidget {
  final IconData icon;
  final Color color;
  final String message;

  const ResultPanel({
    super.key,
    required this.icon,
    required this.color,
    required this.message,
  });

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.all(14),
      decoration: BoxDecoration(
        color: surfaceRaised,
        border: Border.all(color: color.withValues(alpha: 0.4)),
        borderRadius: BorderRadius.circular(7),
      ),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Icon(icon, color: color, size: 20),
          const SizedBox(width: 12),
          Expanded(
            child: SelectableText(
              message,
              style: const TextStyle(
                color: textSecondary,
                fontSize: 12,
                height: 1.7,
              ),
            ),
          ),
        ],
      ),
    );
  }
}

class AboutTile extends StatelessWidget {
  final IconData icon;
  final String title;
  final String subtitle;

  const AboutTile({
    super.key,
    required this.icon,
    required this.title,
    required this.subtitle,
  });

  @override
  Widget build(BuildContext context) {
    return ListTile(
      contentPadding: EdgeInsets.zero,
      leading: Icon(icon, color: accent),
      title: Text(
        title,
        style: const TextStyle(
          color: textPrimary,
          fontSize: 13,
          fontWeight: FontWeight.w600,
        ),
      ),
      subtitle: Padding(
        padding: const EdgeInsets.only(top: 5),
        child: Text(
          subtitle,
          style: const TextStyle(color: textMuted, fontSize: 12, height: 1.6),
        ),
      ),
    );
  }
}
